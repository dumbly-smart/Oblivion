"""Offline complete-process load classification from actual public batch wire."""
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from research.attacks.registry import PredictionResult

FEATURE_NAMES = ('arrival_count','emission_count','frame_bytes_mean','frame_bytes_std',
                 'public_slot_count','public_destination_count','slot_entropy',
                 'arrival_gap_mean','arrival_gap_std','arrival_gap_p10','arrival_gap_p50','arrival_gap_p90',
                 'emission_gap_mean','emission_gap_std','emission_gap_p90',
                 'queue_wait_mean','queue_wait_std','queue_wait_p50','queue_wait_p95',
                 'batch_frames_mean','batch_frames_std','wire_body_byte20_equals_one_fraction')


def number(value, upper=10**15):
    if type(value) is not int or not 0 <= value <= upper:
        raise ValueError('bounded nonnegative integer required')
    return value


def frame(value, epoch, slot):
    if not isinstance(value,list) or len(value)!=164:
        raise ValueError('164-byte frame required')
    for byte in value: number(byte,255)
    header=list(b'OBLV'+bytes([0,1,1,0])+epoch.to_bytes(8,'big')+slot.to_bytes(4,'big'))
    if value[:20]!=header: raise ValueError('public frame header mismatch')


def features(trace):
    if not isinstance(trace,list) or not 6 <= len(trace) <= 4160:
        raise ValueError('bounded complete process trace required')
    arrivals,emissions={},{}
    for row in trace:
        if not isinstance(row,dict): raise ValueError('observer objects required')
        if row.get('type')=='arrival':
            if set(row)!={'type','epoch','slot','arrived_ns','destination','frame'}: raise ValueError('arrival schema')
            epoch=number(row['epoch'],63);slot=number(row['slot'],63);number(row['arrived_ns'])
            if row['destination']!='batcher' or (epoch,slot) in arrivals: raise ValueError('arrival destination/duplicate')
            frame(row['frame'],epoch,slot);arrivals[epoch,slot]=row
        elif row.get('type')=='emission':
            if set(row)!={'type','epoch','emitted_ns','destination','frames'}: raise ValueError('emission schema')
            epoch=number(row['epoch'],63);number(row['emitted_ns'])
            if row['destination']!='executor' or epoch in emissions: raise ValueError('emission destination/duplicate')
            if not isinstance(row['frames'],list) or not 2 <= len(row['frames']) <= 64: raise ValueError('batch frame bound')
            for slot,value in enumerate(row['frames']):frame(value,epoch,slot)
            emissions[epoch]=row
        else: raise ValueError('unknown observer event')
    if not emissions or set(emissions)!=set(range(len(emissions))): raise ValueError('complete contiguous epochs required')
    slots=len(emissions[0]['frames'])
    expected={(epoch,slot) for epoch in emissions for slot in range(slots)}
    if set(arrivals)!=expected or any(len(e['frames'])!=slots for e in emissions.values()): raise ValueError('complete fixed enrolled slots required')
    waits=[]
    for (epoch,slot),arrival in arrivals.items():
        emission=emissions[epoch]
        if emission['emitted_ns']<arrival['arrived_ns'] or emission['frames'][slot]!=arrival['frame']:
            raise ValueError('emission precedes arrival or modifies frame')
        waits.append(emission['emitted_ns']-arrival['arrived_ns'])
    arrival_times=sorted(a['arrived_ns'] for a in arrivals.values())
    emission_times=[emissions[e]['emitted_ns'] for e in sorted(emissions)]
    if emission_times!=sorted(emission_times):raise ValueError('nonmonotonic epochs')
    ag=np.diff(arrival_times);eg=np.diff(emission_times)
    if not len(eg):raise ValueError('at least two epochs required')
    lengths=[len(a['frame']) for a in arrivals.values()]
    counts=[len(e['frames']) for e in emissions.values()]
    # All values derive from observer rows; no target label or private timing plan.
    return np.asarray([len(arrivals),len(emissions),np.mean(lengths),np.std(lengths),slots,2,np.log2(slots),
                       np.mean(ag),np.std(ag),*np.quantile(ag,[.1,.5,.9]),
                       np.mean(eg),np.std(eg),np.quantile(eg,.9),
                       np.mean(waits),np.std(waits),np.median(waits),np.quantile(waits,.95),
                       np.mean(counts),np.std(counts),np.mean([a['frame'][20]==1 for a in arrivals.values()])],dtype=float)


class BatchLoadAttack:
    """Bounded RF over whole-process joint features; no calibrated confidence."""
    def fit(self,profiles,seed=0):
        number(seed,2**32-1)
        if not isinstance(profiles,list) or not 6 <= len(profiles) <= 60: raise ValueError('6..60 independent profile processes required')
        identifiers=set();x=[];y=[]
        for item in profiles:
            if not isinstance(item,dict) or set(item)!={'process_id','label','observations'}:raise ValueError('profile schema')
            identifier=item['process_id']
            if not isinstance(identifier,str) or not 1 <= len(identifier) <= 128 or identifier in identifiers:raise ValueError('unique process IDs required')
            number(item['label'],2);identifiers.add(identifier)
            x.append(features(item['observations']));y.append(item['label'])
        if set(y)!={0,1,2}:raise ValueError('all three authorized profile classes required')
        self.model=RandomForestClassifier(n_estimators=64,max_depth=4,random_state=seed,n_jobs=1,class_weight='balanced')
        self.model.fit(x,y);self.profile_ids=identifiers
        return self

    def run(self,trace,aux):
        if not isinstance(aux,dict) or set(aux)-{'profiles','process_id','seed'} or 'process_id' not in aux:raise ValueError('auxiliary schema')
        if 'profiles' in aux:self.fit(aux['profiles'],aux.get('seed',0))
        if not hasattr(self,'model'):raise ValueError('fit independent authorized profiles first')
        identifier=aux['process_id']
        if not isinstance(identifier,str) or not 1 <= len(identifier) <= 128 or identifier in self.profile_ids:raise ValueError('held-out target process ID required')
        prediction=int(self.model.predict([features(trace)])[0])
        return PredictionResult([prediction],None,{'unit':'complete process','feature_names':list(FEATURE_NAMES),
                'profile_processes':len(self.profile_ids),'model':'RandomForestClassifier(64 trees,max_depth=4)',
                'limitations':'Small supervised feature attack; public bytes and metadata only; uncalibrated; no security proof.'})
