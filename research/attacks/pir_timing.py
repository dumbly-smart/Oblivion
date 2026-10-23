"""Bounded sklearn classifier for one noncolluding PIR server's observations."""
import math
from research.attacks.registry import PredictionResult

FIELDS = {'session','step','server_ns','query_bytes','visible_index'}
FEATURE_MODES = ('joint','timing_only','share_only','visible_index_only')


def vectors(rows, feature_mode):
    if not isinstance(rows,list) or not 1<=len(rows)<=10000:
        raise ValueError('bounded observer rows required')
    width=None;values=[]
    for row in rows:
        if not isinstance(row,dict) or set(row)!=FIELDS:
            raise ValueError('strict single-server observer schema required')
        if not isinstance(row['session'],str) or not 1<=len(row['session'])<=128:
            raise ValueError('invalid observer session')
        for field in ('step','server_ns'):
            if type(row[field]) is not int or not 0<=row[field]<=10**15:
                raise ValueError('invalid observer integer')
        query=row['query_bytes'];index=row['visible_index']
        if not isinstance(query,list) or len(query)>4096 or any(type(v) is not int or not 0<=v<=255 for v in query):
            raise ValueError('invalid single-server query bytes')
        if index is not None and (type(index) is not int or not 0<=index<=1000000):
            raise ValueError('invalid visible index')
        if width is not None and len(query)!=width:
            raise ValueError('query shape must be fixed')
        width=len(query)
        timing=[math.log1p(row['server_ns'])];visible=[-1 if index is None else index]
        features={'joint':timing+visible+query,'timing_only':timing,'share_only':query,'visible_index_only':visible}[feature_mode]
        if not features:raise ValueError('empty features')
        values.append(features)
    for session in {r['session'] for r in rows}:
        steps=sorted(r['step'] for r in rows if r['session']==session)
        if steps != list(range(len(steps))):
            raise ValueError('session rows must have complete contiguous unique steps')
    return values,width


def session_set(rows,aux,key):
    ids=aux.get(key)
    if not isinstance(ids,list) or len(ids)<2 or any(not isinstance(s,str) for s in ids) or len(ids)!=len(set(ids)) or set(ids)!={r['session'] for r in rows}:
        raise ValueError('declare exact distinct whole observer sessions, at least two')
    return set(ids)


class PirTimingAttack:
    def __init__(self,feature_mode='joint',seed=1907):
        if feature_mode not in FEATURE_MODES or type(seed) is not int or not 0<=seed<2**32:
            raise ValueError('invalid feature mode or model seed')
        self.feature_mode=feature_mode;self.seed=seed

    def fit(self,trace,aux):
        if not isinstance(aux,dict) or set(aux)!={'profile_labels','profile_session_ids'}:
            raise ValueError('strict profiling auxiliary schema required')
        x,self.width=vectors(trace,self.feature_mode);labels=aux['profile_labels']
        if not isinstance(labels,list) or len(labels)!=len(x) or any(type(y) is not int or y not in (0,1,2) for y in labels) or set(labels)!={0,1,2}:
            raise ValueError('three-class independent profiling labels required')
        self.profile_sessions=session_set(trace,aux,'profile_session_ids')
        from sklearn.ensemble import RandomForestClassifier
        self.model=RandomForestClassifier(n_estimators=64,max_depth=5,min_samples_leaf=3,max_features=1.0,class_weight='balanced',random_state=self.seed,n_jobs=1).fit(x,labels)
        return self

    def run(self,trace,aux):
        if not isinstance(aux,dict) or set(aux)!={'target_session_ids'} or not hasattr(self,'model'):
            raise ValueError('fit before running with exact target session schema')
        x,width=vectors(trace,self.feature_mode)
        if width!=self.width:raise ValueError('profiling/target query shape differs')
        if session_set(trace,aux,'target_session_ids') & self.profile_sessions:
            raise ValueError('profile and target sessions must be disjoint')
        scores=self.model.predict_proba(x).tolist()
        return PredictionResult(self.model.predict(x).tolist(),None,dict(
            algorithm='sklearn RandomForestClassifier:64trees/depth5/minleaf3/allfeatures',feature_mode=self.feature_mode,
            score_semantics='UNCALIBRATED tree class proportions',original_scores=scores,seed=self.seed,
            prediction_unit='requested target class per server observation',
            features='log1p server answer ns; own query bytes; visible direct index only in plaintext control',
            knowledge='public mechanism/geometry and labeled whole independent profiling sessions; no target labels',
            limitations='One noncolluding server, local exported observables and three requested indices; not a network adversary, privacy proof, or calibrated probability.'))
