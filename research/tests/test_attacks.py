import unittest
from research.attacks.simple import FrequencyAttack, TrafficAttack, split_sessions

class Attacks(unittest.TestCase):
    def test_frequency_uses_auxiliary_popularity_without_truth(self):
        view=[{"tag":9}]*75+[{"tag":2}]*25
        result=FrequencyAttack().run(view,{"ranked_labels":[0,1],"majority":0})
        self.assertEqual(result.predictions,[0]*75+[1]*25)

    def test_traffic_learns_profile_and_predicts_held_out_sizes(self):
        attacker=TrafficAttack()
        attacker.fit([{"bytes":64,"latency_ns":7},{"bytes":4,"latency_ns":9}],[0,1])
        result=attacker.run([{"bytes":4,"latency_ns":100},{"bytes":64,"latency_ns":100}],{})
        self.assertEqual(result.predictions,[1,0])

    def test_entire_sessions_stay_in_one_partition(self):
        train,test=split_sessions({"a":[1,2],"b":[3,4],"c":[5],"d":[6]})
        self.assertEqual(set(train),{"a","b"})
        self.assertEqual(set(test),{"c","d"})
        self.assertFalse(set(train)&set(test))

if __name__=="__main__":unittest.main()

class Uncertainty(unittest.TestCase):
    def test_shared_profile_sessions_are_resampled_as_a_trial(self):
        from research.analysis.leakage import bootstrap
        interval=bootstrap([1.0]*20+[0.0]*20,clusters=[0]*20+[1]*20)
        self.assertEqual(interval,[0.0,1.0])
