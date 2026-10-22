import unittest
from research.attacks.linkability import recover_links

class UpdateLinkability(unittest.TestCase):
    def test_stable_tag_immediately_links_and_next_search_links_addresses(self):
        rows=[{'mode':'control','phase':'past_search','slot':0,'request':{'tag':[1]},'response':{'entries':[{'address':[8]}]}},
              {'mode':'control','phase':'injected_update','injection':0,'request':{'stable_tag':[1],'address':[9]}},
              {'mode':'control','phase':'fresh_search','slot':0,'request':{'tag':[1]},'response':{'entries':[{'address':[8]},{'address':[9]}]}}]
        result=recover_links(rows,'control',seed=9)
        self.assertEqual(result['before_predictions'],[0]);self.assertEqual(result['after_predictions'],[0]);self.assertEqual(result['before_matches'],1)
    def test_fresh_address_is_not_a_past_authorized_posting(self):
        rows=[{'mode':'ggm','phase':'past_search','slot':0,'request':{'tag':[1]},'response':{'entries':[{'address':[8]}]}},
              {'mode':'ggm','phase':'injected_update','injection':0,'request':{'address':[9]}},
              {'mode':'ggm','phase':'fresh_search','slot':0,'request':{'tag':[1]},'response':{'entries':[{'address':[8]},{'address':[9]}]}}]
        result=recover_links(rows,'ggm',seed=9)
        self.assertEqual(result['before_matches'],0);self.assertEqual(result['after_matches'],1)
        with self.assertRaises(ValueError):recover_links(rows[:-1],'ggm',seed=9)
