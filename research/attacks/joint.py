"""Bounded supervised forest over whitelisted joint interface observations.

Independent profiling is explicit auxiliary knowledge. No published attack
reproduction or statistical-to-cryptographic reduction is claimed.
"""
from dataclasses import dataclass
import numpy as np
from research.attacks.simple import AttackResult

FEATURES=('request_bytes','response_bytes','registry_bytes','registry_index',
          'storage_events','storage_bytes','last_bucket','storage_span_ns',
          'latency_ns','late_by_ns','instance_count','cold_start_ns')

def vector(rows):
    if any(set(row)&{'label','real','function','status','work_ns'} for row in rows):
        raise ValueError('private fields are forbidden in attacker input')
    values=np.asarray([[row[key] for key in FEATURES] for row in rows],dtype=float)
    if values.ndim!=2 or values.shape[1]!=len(FEATURES) or not np.isfinite(values).all():
        raise ValueError('invalid observer values')
    return values

@dataclass
class Node:
    probabilities: np.ndarray
    feature: int = -1
    threshold: float = 0
    left: object = None
    right: object = None

class JointAttack:
    def __init__(self,seed=1,trees=32,depth=5,min_leaf=3):
        self.seed=seed;self.trees=trees;self.depth=depth;self.min_leaf=min_leaf
    def fit(self,trace,known_profile_labels):
        x=vector(trace);y=np.asarray(known_profile_labels,dtype=int)
        if len(x)!=len(y) or len(y)<4 or set(y)!={0,1,2}:
            raise ValueError('need labeled independent profiles covering all three classes')
        self.rng=np.random.default_rng(self.seed)
        self.models=[]
        for _ in range(self.trees):
            indices=self.rng.integers(0,len(y),len(y))
            self.models.append(self._build(x[indices],y[indices],self.depth))
        return self
    def _build(self,x,y,depth):
        counts=np.bincount(y,minlength=3);p=(counts+1)/(len(y)+3)
        node=Node(p)
        if depth==0 or len(y)<2*self.min_leaf or np.count_nonzero(counts)==1:return node
        best_loss=len(y)*(1-np.sum((counts/len(y))**2));best=None
        features=self.rng.choice(x.shape[1],max(1,int(np.sqrt(x.shape[1]))),replace=False)
        for feature in features:
            unique=np.unique(x[:,feature])
            thresholds=(unique[1:]+unique[:-1])/2
            if len(thresholds)>16:thresholds=np.quantile(thresholds,np.linspace(0,1,16))
            for threshold in thresholds:
                mask=x[:,feature]<=threshold;n=int(mask.sum())
                if min(n,len(y)-n)<self.min_leaf:continue
                loss=0
                for side in (mask,~mask):
                    c=np.bincount(y[side],minlength=3);size=len(y[side]);loss+=size*(1-np.sum((c/size)**2))
                if loss<best_loss-1e-10:best_loss=loss;best=(feature,float(threshold),mask)
        if best:
            feature,threshold,mask=best;node.feature=int(feature);node.threshold=threshold
            node.left=self._build(x[mask],y[mask],depth-1);node.right=self._build(x[~mask],y[~mask],depth-1)
        return node
    def run(self,trace,auxiliary_knowledge):
        x=vector(trace);scores=[]
        for row in x:
            votes=[]
            for node in self.models:
                while node.feature>=0:node=node.left if row[node.feature]<=node.threshold else node.right
                votes.append(node.probabilities)
            scores.append(np.mean(votes,axis=0).tolist())
        return AttackResult(np.argmax(scores,axis=1).tolist(),scores,{
            'algorithm':'bootstrap ensemble of bounded axis-aligned classification trees',
            'trees':self.trees,'depth':self.depth,'minimum_profile_leaf':self.min_leaf,
            'features':list(FEATURES),'seed':self.seed,
            'knowledge':'public mechanisms and separately labeled whole profiling sessions',
            'scores':'smoothed leaf frequencies averaged across trees, not calibrated guarantees'})
