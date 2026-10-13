import importlib.util, io, plistlib, tempfile, unittest, zipfile
from pathlib import Path

spec=importlib.util.spec_from_file_location('inspect_ipa',str(Path(__file__).resolve().parents[1]/'scripts/inspect_ipa.py'))
mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
class InspectIPATest(unittest.TestCase):
    def test_basic_ipa(self):
        with tempfile.TemporaryDirectory() as d:
            ipa=Path(d)/'demo.ipa'
            with zipfile.ZipFile(ipa,'w') as z:
                z.writestr('Payload/Demo.app/Info.plist',plistlib.dumps({'CFBundleIdentifier':'AlexisBarreyat.BeReal','CFBundleShortVersionString':'4.93.0','CFBundleVersion':'1','MinimumOSVersion':'17.0','CFBundleExecutable':'Demo'}))
                z.writestr('Payload/Demo.app/Demo',bytes.fromhex('cffaedfe')+b'\0'*64)
            actual=mod.inspect(ipa)
            self.assertEqual(actual['version'],'4.93.0')
            self.assertEqual(actual['executable_bytes'],68)
    def test_missing_metadata(self):
        with tempfile.TemporaryDirectory() as d:
            ipa=Path(d)/'bad.ipa'
            with zipfile.ZipFile(ipa,'w') as z:z.writestr('Payload/foo.txt','bad')
            with self.assertRaises(ValueError):mod.inspect(ipa)
if __name__=='__main__':unittest.main()
