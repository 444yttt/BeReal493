"""Bundle lookup routing tests; no signing assets or network are used."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch


spec = importlib.util.spec_from_file_location('bereal_bundle_lookup', Path(__file__).parents[1] / 'scripts/bereal-resign.py')
signer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(signer)
IDENTIFIER = signer.ROOT_ID
CERTIFICATE = {'id': 'offline-certificate'}
DEVICE = {'id': 'offline-device', 'attributes': {'udid': 'offline-device-identifier'}}
PROFILE = {'id': 'offline-profile', 'attributes': {'profileType': 'IOS_APP_ADHOC',
           'profileState': 'ACTIVE', 'profileContent': 'offline-content'}}


def bundle(identifier, resource_id, platform='IOS'):
    return {'id': resource_id, 'attributes': {'identifier': identifier, 'platform': platform}}


class ExactBundleLookupTest(unittest.TestCase):
    def call(self, api):
        return signer.get_profile(api, CERTIFICATE, b'offline-cert-der', 'ABCDEFGHIJ', IDENTIFIER, DEVICE)

    def test_wide_results_reuse_only_exact_ios_registration_and_profile(self):
        api = Mock()
        api.collection.side_effect = [[
            bundle('com.ayato.y3posclient', 'unrelated'),
            bundle(IDENTIFIER + '.prefix-suffix', 'prefix-match'),
            bundle(IDENTIFIER, 'exact')], [PROFILE]]
        with patch.object(signer, 'validate_profile', return_value=(b'raw-profile', {})) as validate:
            self.assertEqual(self.call(api), (b'raw-profile', {}))
        self.assertEqual(api.collection.call_args_list[1].args[0], '/v1/bundleIds/exact/profiles')
        self.assertEqual(api.collection.call_args_list[0].args[1], {'filter[identifier]': IDENTIFIER})
        validate.assert_called_once_with(PROFILE, b'offline-cert-der', 'ABCDEFGHIJ', IDENTIFIER,
                                         'offline-device-identifier')
        api.request.assert_not_called()

    def test_wide_results_without_exact_match_create_only_requested_scope(self):
        api = Mock()
        api.collection.side_effect = [[bundle(IDENTIFIER + '.prefix-suffix', 'prefix-match'),
                                       bundle('com.unrelated.app', 'unrelated', 'MAC_OS')], []]
        api.request.side_effect = [{'data': bundle(IDENTIFIER, 'new-exact')}, {'data': PROFILE}]
        with patch.object(signer, 'validate_profile', return_value=(b'raw-profile', {})):
            self.call(api)
        writes = api.request.call_args_list
        self.assertEqual(len(writes), 2)
        self.assertEqual(writes[0].args[:2], ('POST', '/v1/bundleIds'))
        self.assertEqual(writes[0].args[2]['data']['attributes']['identifier'], IDENTIFIER)
        self.assertEqual(writes[0].args[2]['data']['attributes']['platform'], 'IOS')
        self.assertEqual(writes[1].args[:2], ('POST', '/v1/profiles'))
        self.assertEqual(writes[1].args[2]['data']['relationships']['bundleId']['data']['id'], 'new-exact')
        self.assertEqual(api.collection.call_args_list[1].args[0], '/v1/bundleIds/new-exact/profiles')

    def test_empty_results_create_scoped_registration(self):
        api = Mock(); api.collection.side_effect = [[], [PROFILE]]
        api.request.return_value = {'data': bundle(IDENTIFIER, 'new-exact')}
        with patch.object(signer, 'validate_profile', return_value=(b'raw-profile', {})):
            self.call(api)
        self.assertEqual(api.request.call_count, 1)
        self.assertEqual(api.request.call_args.args[:2], ('POST', '/v1/bundleIds'))
        self.assertEqual(api.request.call_args.args[2]['data']['attributes']['identifier'], IDENTIFIER)

    def test_true_exact_duplicates_fail_before_any_write(self):
        api = Mock(); api.collection.return_value = [bundle('com.unrelated.app', 'unrelated'),
            bundle(IDENTIFIER, 'exact-one'), bundle(IDENTIFIER, 'exact-two')]
        with self.assertRaisesRegex(RuntimeError, 'Ambiguous bundle registration'):
            self.call(api)
        api.request.assert_not_called(); self.assertEqual(api.collection.call_count, 1)

    def test_exact_wrong_platform_fails_before_any_write(self):
        api = Mock(); api.collection.return_value = [bundle(IDENTIFIER + '.prefix-suffix', 'prefix-match'),
                                                   bundle(IDENTIFIER, 'exact-mac', 'MAC_OS')]
        with self.assertRaisesRegex(RuntimeError, 'Unexpected bundle registration'):
            self.call(api)
        api.request.assert_not_called(); self.assertEqual(api.collection.call_count, 1)

    def test_universal_registration_reuses_strict_ios_profile_without_writes(self):
        api = Mock(); api.collection.side_effect = [[bundle('com.unrelated.app', 'unrelated', 'MAC_OS'),
                                                   bundle(IDENTIFIER, 'exact-universal', 'UNIVERSAL')], [PROFILE]]
        with patch.object(signer, 'validate_profile', return_value=(b'raw-profile', {})) as validate:
            self.call(api)
        self.assertEqual(api.collection.call_args_list[0].args[1], {'filter[identifier]': IDENTIFIER})
        self.assertEqual(api.collection.call_args_list[1].args[0], '/v1/bundleIds/exact-universal/profiles')
        validate.assert_called_once_with(PROFILE, b'offline-cert-der', 'ABCDEFGHIJ', IDENTIFIER,
                                         'offline-device-identifier')
        api.request.assert_not_called()

    def test_ios_create_normalized_to_universal_is_valid(self):
        api = Mock(); api.collection.side_effect = [[], [PROFILE]]
        api.request.return_value = {'data': bundle(IDENTIFIER, 'new-universal', 'UNIVERSAL')}
        with patch.object(signer, 'validate_profile', return_value=(b'raw-profile', {})):
            self.call(api)
        self.assertEqual(api.request.call_args.args[:2], ('POST', '/v1/bundleIds'))
        self.assertEqual(api.request.call_args.args[2]['data']['attributes']['platform'], 'IOS')
        self.assertEqual(api.collection.call_args_list[1].args[0], '/v1/bundleIds/new-universal/profiles')

    def test_unknown_or_missing_registration_platform_fails_before_writes(self):
        for platform in ('TV_OS', 'UNKNOWN', '', None):
            api = Mock(); api.collection.return_value = [bundle(IDENTIFIER, 'invalid-platform', platform)]
            with self.subTest(platform=platform), self.assertRaisesRegex(RuntimeError, 'Unexpected bundle registration'):
                self.call(api)
            api.request.assert_not_called(); self.assertEqual(api.collection.call_count, 1)

    def test_wrong_create_response_stops_before_profile_reads_or_creation(self):
        for platform in ('MAC_OS', 'UNKNOWN', None):
            api = Mock(); api.collection.return_value = []
            api.request.return_value = {'data': bundle(IDENTIFIER, 'wrong-created-platform', platform)}
            with self.subTest(platform=platform), self.assertRaisesRegex(RuntimeError, 'Unexpected bundle registration'):
                self.call(api)
            self.assertEqual(api.collection.call_count, 1)
            self.assertEqual(api.request.call_count, 1)
            self.assertEqual(api.request.call_args.args[:2], ('POST', '/v1/bundleIds'))


if __name__ == '__main__': unittest.main()
