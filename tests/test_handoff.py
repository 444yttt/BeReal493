from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

class HandoffTest(unittest.TestCase):
    def test_handoff_contract(self):
        text = (ROOT/'AGENTS.md').read_text()
        for phrase in ('non-jailbroken iPhone','4.93.0','test post succeeded','private'):
            self.assertIn(phrase, text)

    def test_source_explicitly_prototype(self):
        text=(ROOT/'Tweak.m').read_text()
        self.assertIn('BRPrototypeTwoPhotosReady', text)
        self.assertIn('DOES NOT submit', text)
