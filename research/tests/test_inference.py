import unittest
import numpy as np
from research.attacks.inference import statistics, infer, exhaustive, iterative_hungarian, linear_assignment, objective


class NumericalInference(unittest.TestCase):
    def fixture(self):
        auxiliary = {'counts':[2,8,15], 'corpus_documents':20, 'profile_labels':[0,1,2]*40+[2]*10}
        observations = [{'tag':str(label), 'count':[2,8,15][label]} for label in [2,0,1]*8]
        return observations, auxiliary

    def test_positive_likelihood_control_without_target_labels(self):
        observations, auxiliary = self.fixture()
        for result in infer(observations, auxiliary).values():
            self.assertEqual([rank[0] for rank in result['rankings']], [2,0,1]*8)

    def test_hungarian_equals_exhaustive_optimum(self):
        rng = np.random.default_rng(4)
        for m in [1,2,3,4]:
            unary = rng.normal(size=(m,4))
            stats = {'iid_unary':unary}
            mapping = linear_assignment(unary)
            exact, value, marginal = exhaustive(stats)
            self.assertAlmostEqual(unary[np.arange(m),mapping].sum(), value)
            np.testing.assert_allclose(marginal.sum(axis=1), 1)

    def test_iterative_steps_monotone_and_bounded_by_exact(self):
        observations, auxiliary = self.fixture()
        stats = statistics(observations, auxiliary)
        mapping, history = iterative_hungarian(stats, seed=9)
        _, exact, _ = exhaustive(stats, markov=True)
        self.assertTrue(all(a < b for a,b in zip(history, history[1:])))
        self.assertLessEqual(history[-1], exact+1e-8)
        self.assertAlmostEqual(history[-1], objective(mapping,stats['markov_unary'],stats['transition_counts'],stats['transition_log_probability']))

    def test_known_padding_removes_count_model(self):
        observations, auxiliary = self.fixture()
        stats = statistics(observations, auxiliary, padded=True)
        auxiliary2 = dict(auxiliary,counts=[18,17,1])
        np.testing.assert_allclose(stats['iid_unary'], statistics(observations,auxiliary2,padded=True)['iid_unary'])

    def test_missing_tokens_get_injective_assignment(self):
        observations, auxiliary = self.fixture()
        results = infer(observations[:1], auxiliary)
        self.assertTrue(all(len(set(r['mapping'])) == 1 for r in results.values()))

    def test_static_model_rejects_changing_counts(self):
        observations, auxiliary = self.fixture()
        observations.append({'tag':'2','count':18})
        with self.assertRaises(ValueError):
            statistics(observations, auxiliary)


if __name__ == '__main__':
    unittest.main()
