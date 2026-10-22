import unittest
from research.attacks.joint import JointAttack, FEATURES
from research.analysis.system import trial_interval, nondominated

class SystemAttacks(unittest.TestCase):
    def test_leaky_control_and_unknown_truth_rejection(self):
        rows=[{feature:0.0 for feature in FEATURES} for _ in range(120)]
        labels=[i%3 for i in range(120)]
        for row,label in zip(rows,labels):row['registry_index']=label
        attack=JointAttack(seed=9).fit(rows,labels)
        self.assertEqual(attack.run(rows,{}).predictions,labels)
        with self.assertRaises(ValueError):attack.run([dict(rows[0],label=0)],{})
    def test_constant_observer_can_only_use_profile_prior(self):
        rows=[dict.fromkeys(FEATURES,1.0) for _ in range(40)]
        labels=[0]*20+[1]*10+[2]*10
        result=JointAttack(seed=4).fit(rows,labels).run(rows,{})
        self.assertEqual(set(result.predictions),{0})
        self.assertTrue(all(abs(sum(p)-1)<1e-9 for p in result.scores))
    def test_interval_resamples_trials_and_pareto(self):
        low,high=trial_interval([0.2,0.2,0.2],seed=3)
        self.assertAlmostEqual(low,.2);self.assertAlmostEqual(high,.2)
        self.assertEqual(nondominated([(1,2),(2,1),(3,3)]),[0,1])

if __name__=='__main__':unittest.main()
