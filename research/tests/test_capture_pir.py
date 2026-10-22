"""Behavioral checks for capture scope and fail-closed drop accounting."""
import importlib.util
from pathlib import Path
import unittest
import json

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('capture_pir',ROOT/'scripts/capture_pir.py')
capture=importlib.util.module_from_spec(spec)
spec.loader.exec_module(capture)

class CaptureTests(unittest.TestCase):
    def summary(self,received=20,dropped=0,components=(0,0,0,0)):
        return [f"Packets received/dropped on interface 'Loopback: lo': {received}/{dropped} (pcap:{components[0]}/dumpcap:{components[1]}/flushed:{components[2]}/ps_ifdrop:{components[3]}) (100.0%)"]

    def test_drop_counters_required_and_all_components_checked(self):
        self.assertEqual(capture.capture_statistics(self.summary())['received'],20)
        for log in ([],['malformed'],self.summary()+self.summary(),self.summary(dropped=1),*[self.summary(components=tuple(int(j==i) for j in range(4))) for i in range(4)]):
            with self.subTest(log=log),self.assertRaises(ValueError):capture.capture_statistics(log)

    def test_only_owned_loopback_ports_accepted(self):
        packet={'ip.src':'127.0.0.1','ip.dst':'127.0.0.1','source_port':10101,'destination_port':55555}
        capture.validate_owned_packets([packet],[10101,10102])
        for row,ports in ((dict(packet,source_port=10103),[10101,10102]),(dict(packet,**{'ip.dst':'192.0.2.1'}),[10101,10102]),(packet,[10101,10101])):
            with self.subTest(row=row,ports=ports),self.assertRaises(ValueError):capture.validate_owned_packets([row],ports)

    def test_real_capture_has_complete_zero_drop_stream_accounting(self):
        output=ROOT/'experiments/results/pir-capture-current'
        if not output.exists():self.skipTest('measurement artifacts unavailable')
        report=json.loads((output/'structural-diagnostics.json').read_text())
        self.assertEqual((report['captured_trials'],report['verified_queries'],report['verified_streams']),(30,3000,6000))
        launches=json.loads((output/'launches.json').read_text())
        for launch in launches:
            stats=capture.capture_statistics(launch['capture_log'])
            packets=capture.lines(output/f"trial-{launch['trial']:03}"/'packet-observer.jsonl')
            capture.validate_owned_packets(packets,launch['ready']['ports'])
            self.assertEqual(stats['received'],len(packets))
        self.assertNotIn('limited_packet_feature_test',report)

if __name__=='__main__':unittest.main()
