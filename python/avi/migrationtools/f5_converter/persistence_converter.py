import logging
import avi.migrationtools.f5_converter.converter_constants as final
import avi.migrationtools.f5_converter.converter_constants as conv_const
from avi.migrationtools.f5_converter.profile_converter import ProfileConfigConv
from avi.migrationtools.f5_converter.conversion_util import F5Util
LOG = logging.getLogger(__name__)
# Creating f5 object for util library.
conv_utils = F5Util()


class PersistenceConfigConv(object):
    @classmethod
    def get_instance(cls, version, f5_persistence_attributes, prefix,
                     object_merge_check):
        if version == '10':
            return PersistenceConfigConvV10(f5_persistence_attributes, prefix,
                                            object_merge_check)
        if version in ['11', '12']:
            return PersistenceConfigConvV11(f5_persistence_attributes, prefix,
                                            object_merge_check)

    def convert_cookie_persistence(self, name, profile):
        pass

    def convert_cookie(self, name, profile, skipped, tenant):
        pass

    def convert_ssl(self, name, profile, skipped, indirect_mappings, tenant):
        pass

    def convert_source_addr(self, name, profile, skipped, tenant):
        pass

    def update_conversion_status(self, conv_status, persist_mode, name,
                                 persist_profile):
        pass

    def update_conv_status_for_error(self, name, persist_mode, key):
        pass

    def update_conv_status_for_skip(self, persist_mode, name):
        pass

    def convert(self, f5_config, avi_config, user_ignore, tenant_ref,
                merge_object_mapping, sys_dict):
        avi_config['hash_algorithm'] = []
        converted_objs = []
        f5_persistence_dict = f5_config.get('persistence')
        user_ignore = user_ignore.get('persistence', {})
        # Added variable to get total object count.
        progressbar_count = 0
        total_size = len(f5_persistence_dict.keys())
        print "Converting Persistence Profiles..."
        for key in f5_persistence_dict.keys():
            progressbar_count += 1
            persist_mode = None
            name = None
            skipped = []
            # Added call to check the progress.
            msg = "persistence conversion started..."
            conv_utils.print_progress_bar(progressbar_count, total_size, msg,
                             prefix='Progress', suffix='')
            try:
                persist_mode, name = key.split(" ")
                LOG.debug("Converting persistence profile: %s" % name)
                profile = f5_persistence_dict[key]
                prof_conv = ProfileConfigConv()
                profile = prof_conv.update_with_default_profile(
                    persist_mode, profile, f5_persistence_dict, name)
                tenant, name = conv_utils.get_tenant_ref(name)
                if tenant_ref != 'admin':
                    tenant = tenant_ref
                # TODO: Should be enabled after controller app cookie issue is fixed
                # if persist_mode == "cookie":
                #     persist_profile = self.convert_cookie(name, profile,
                #                                           skipped, tenant)
                #     if not persist_profile:
                #         continue
                #     u_ignore = user_ignore.get('cookie', [])
                if persist_mode == "ssl":
                    persist_profile = self.convert_ssl(
                        name, profile, skipped, self.indirect, tenant)
                    u_ignore = user_ignore.get('ssl', [])
                elif persist_mode == "source-addr":
                    persist_profile = self.convert_source_addr(
                        name, profile, skipped, tenant)
                    u_ignore = user_ignore.get('source-addr', [])
                elif persist_mode == "hash":
                    avi_config['hash_algorithm'].append(name)
                    skipped = profile.keys()
                    LOG.warn('hash-persistence profile %s will be mapped '
                             'indirectly to Pool -> Load Balance  Algorithm'
                             % name)
                    conv_status = {
                        'status': conv_const.STATUS_PARTIAL,
                        'skipped': skipped
                    }
                    msg = 'Indirectly mapped to Pool -> Load Balance Algorithm'
                    conv_utils.add_conv_status(
                        'profile', "hash-persistence", name, conv_status, msg)
                    continue
                else:
                    LOG.warning(
                        'persist mode not supported skipping conversion: %s' %
                        name)
                    self.update_conv_status_for_skip(persist_mode, name)
                    continue
                if not persist_profile:
                    continue
                # code to merge applicaation persistence profile.
                if self.object_merge_check:
                    conv_utils.update_skip_duplicates(persist_profile,
                                    avi_config['ApplicationPersistenceProfile'],
                                    'app_per_profile', converted_objs, name,
                                    None, merge_object_mapping, persist_mode,
                         self.prefix, sys_dict['ApplicationPersistenceProfile'])
                    self.app_per_count += 1
                else:
                    avi_config["ApplicationPersistenceProfile"].append(
                        persist_profile)

                ignore_for_defaults = {"app-service": "none", "mask": "none"}
                conv_status = conv_utils.get_conv_status(
                    skipped, self.indirect, ignore_for_defaults,
                    profile, u_ignore)
                self.update_conversion_status(conv_status, persist_mode,
                                              name, persist_profile)
            except:
                LOG.error("Failed to convert persistance profile : %s" % key,
                          exc_info=True)
                self.update_conv_status_for_error(name, persist_mode, key)
        count = len(avi_config["ApplicationPersistenceProfile"])
        LOG.debug("Converted %s persistence profiles" % count)
        f5_config.pop('persistence')

    def convert_timeout(self, timeout):
        if ':' in str(timeout):
            expiration = timeout.split(':')
            expiration.reverse()
            timeout = 0
            i = 0
            for val in expiration:
                val = int(val)
                if i == 0:
                    timeout = int(val/final.SEC_IN_MIN)
                elif i == 1:
                    timeout += val
                elif i == 2:
                    timeout += (val*final.MIN_IN_HR)
                elif i == 3:
                    timeout += (val*final.MIN_IN_HR*final.HR_IN_DAY)
                i += 1
        else:
            timeout = 1 if int(timeout) == 0 else timeout
        return timeout


class PersistenceConfigConvV11(PersistenceConfigConv):
    def __init__(self, f5_persistence_attributes, prefix, object_merge_check):
        self.indirect = f5_persistence_attributes['Persistence_indirect']
        self.supported_attr = f5_persistence_attributes['Persistence_supported_attr']
        self.supported_attr_convert = f5_persistence_attributes['Persistence_' \
                                            'supported_attr_' \
                                            'convert_source_addr']
        # Added prefix for objects
        self.prefix = prefix
        self.object_merge_check = object_merge_check
        self.app_per_count = 0

    def convert_cookie(self, name, profile, skipped, tenant):
        method = profile.get('method', 'insert')
        if not method == 'insert':
            LOG.warn("Skipped cookie method not supported for profile '%s' "
                     % name)
            conv_utils.add_status_row('persistence', 'cookie', name,
                                      final.STATUS_SKIPPED)
            return None
        #supported_attr = ["cookie-name", "defaults-from", "expiration",
                          #"method"]
        ignore_lst = ['always-send']
        parent_obj = super(PersistenceConfigConvV11, self)
        self.supported_attr += ignore_lst
        skipped += [attr for attr in profile.keys()
                    if attr not in self.supported_attr]
        cookie_name = profile.get("cookie-name", name+':cookie-name')
        timeout = profile.get("expiration", '1')
        timeout = parent_obj.convert_timeout(timeout)
        persist_profile = {
            "name": name,
            "app_cookie_persistence_profile": {
                "prst_hdr_name": cookie_name,
                "timeout": timeout
            },
            "server_hm_down_recovery": "HM_DOWN_PICK_NEW_SERVER",
            "persistence_type": "PERSISTENCE_TYPE_APP_COOKIE",
        }
        persist_profile['tenant_ref'] = conv_utils.get_object_ref(
            tenant, 'tenant')

        return persist_profile

    def convert_ssl(self, name, profile, skipped, indirect_mappings, tenant):
        supported_attr = ['defaults-from']
        skipped += [attr for attr in profile.keys()
                    if attr not in supported_attr]
        indirect_mappings.append("timeout")
        persist_profile = {
            "server_hm_down_recovery": "HM_DOWN_PICK_NEW_SERVER",
            "persistence_type": "PERSISTENCE_TYPE_TLS",
            "name": name
        }
        persist_profile['tenant_ref'] = conv_utils.get_object_ref(
                tenant, 'tenant')
        return persist_profile

    def convert_source_addr(self, name, profile, skipped, tenant):
        supported_attr = self.supported_attr_convert
        ignore_lst = ['map-proxies']
        supported_attr += ignore_lst
        skipped += [attr for attr in profile.keys()
                    if attr not in supported_attr]
        timeout = profile.get("timeout", final.SOURCE_ADDR_TIMEOUT)
        if timeout > 0:
            timeout = int(timeout)/final.SEC_IN_MIN
        persist_profile = {
            "server_hm_down_recovery": "HM_DOWN_PICK_NEW_SERVER",
            "persistence_type": "PERSISTENCE_TYPE_CLIENT_IP_ADDRESS",
            "ip_persistence_profile": {
                "ip_persistent_timeout": timeout
            },
            "name": name
        }
        persist_profile['tenant_ref'] = conv_utils.get_object_ref(
                tenant, 'tenant')
        return persist_profile

    def update_conversion_status(self, conv_status, persist_mode, name,
                                 persist_profile):
        conv_utils.add_conv_status('persistence', persist_mode, name,
                                   conv_status, persist_profile)
        LOG.debug("Conversion successful for persistence profile: %s" %
                  name)

    def update_conv_status_for_error(self, name, persist_mode, key):
        if name:
            conv_utils.add_status_row("persistence", persist_mode, name,
                                      final.STATUS_ERROR)
        else:
            conv_utils.add_status_row("persistence", key, key,
                                      final.STATUS_ERROR)

    def update_conv_status_for_skip(self, persist_mode, name):
        conv_utils.add_status_row("persistence", persist_mode, name,
                                  final.STATUS_SKIPPED)


class PersistenceConfigConvV10(PersistenceConfigConv):
    def __init__(self, f5_persistence_attributes, prefix, object_merge_check):
        self.indirect = f5_persistence_attributes['Persistence_indirect']
        self.supported_attr = \
            f5_persistence_attributes['Persistence_supported_attr']
        self.supported_attr_conver = f5_persistence_attributes[
            'Persistence_supported_attr_convert_source_addr']
        # Added prefix for objects
        self.prefix = prefix
        self.object_merge_check = object_merge_check
        self.app_per_count = 0

    def convert_cookie(self, name, profile, skipped, tenant):
        method = profile.get('cookie mode', 'insert')
        if not method == 'insert':
            LOG.warn("Skipped cookie method not supported for profile '%s' "
                     % name)
            conv_utils.add_conv_status('persistence', 'cookie', name, 'skipped')
            return None
        #supported_attr = ["cookie name", "mode", "defaults from", "cookie mode",
                          #"cookie hash offset", "cookie hash length",
                          #"cookie expiration"]
        skipped += [attr for attr in profile.keys()
                   if attr not in self.supported_attr]
        cookie_name = profile.get("cookie name", name+':-cookie')
        if not cookie_name:
            LOG.error("Missing Required field cookie name in: %s", name)
            conv_utils.add_status_row('profile', 'persist-cookie', name,
                                      final.STATUS_SKIPPED)
            return None
        timeout = profile.get("cookie expiration", '1')
        if timeout == 'immediate':
            timeout = '0'
        parent_obj = super(PersistenceConfigConvV10, self)
        if 'd ' in timeout:
            timeout = timeout.replace('d ', ':')
        elif 'd' in timeout:
            timeout = timeout.replace('d', '')
        timeout = parent_obj.convert_timeout(timeout)
        persist_profile = {
            "name": name,
            "app_cookie_persistence_profile": {
                "prst_hdr_name": cookie_name,
                "timeout": timeout
            },
            "server_hm_down_recovery": "HM_DOWN_PICK_NEW_SERVER",
            "persistence_type": "PERSISTENCE_TYPE_APP_COOKIE",
        }
        persist_profile['tenant_ref'] = conv_utils.get_object_ref(
                tenant, 'tenant')
        return persist_profile

    def convert_ssl(self, name, profile, skipped, indirect, tenant):
        supported_attr = ["mode", 'defaults-from']
        skipped += [attr for attr in profile.keys()
                    if attr not in supported_attr]
        indirect.append("timeout")
        persist_profile = {
            "server_hm_down_recovery": "HM_DOWN_PICK_NEW_SERVER",
            "persistence_type": "PERSISTENCE_TYPE_TLS",
            "name": name
        }
        persist_profile['tenant_ref'] = conv_utils.get_object_ref(
                tenant, 'tenant')
        return persist_profile

    def convert_source_addr(self, name, profile, skipped, tenant):
        supported_attr = self.supported_attr_conver

        skipped += [attr for attr in profile.keys()
                    if attr not in supported_attr]
        timeout = profile.get("timeout", final.SOURCE_ADDR_TIMEOUT)
        if timeout > 0:
            timeout = int(timeout)/final.SEC_IN_MIN
        persist_profile = {
          "server_hm_down_recovery": "HM_DOWN_PICK_NEW_SERVER",
          "persistence_type": "PERSISTENCE_TYPE_CLIENT_IP_ADDRESS",
          "ip_persistence_profile": {
            "ip_persistent_timeout": timeout
          },
          "name": name
        }
        persist_profile['tenant_ref'] = conv_utils.get_object_ref(
                tenant, 'tenant')
        return persist_profile

    def update_conversion_status(self, conv_status, persist_mode, name,
                                 persist_profile):
        conv_utils.add_conv_status('profile', 'persist', name,
                                   conv_status, persist_profile)
        LOG.debug("Conversion successful for persistence profile: %s" %
                  name)

    def update_conv_status_for_error(self, name, persist_mode, key):
        if name:
            conv_utils.add_status_row("profile", 'persist', name,
                                      final.STATUS_ERROR)
        else:
            conv_utils.add_status_row("profile", 'persist', key,
                                      final.STATUS_ERROR)

    def update_conv_status_for_skip(self, persist_mode, name):
        conv_utils.add_status_row("profile", 'persist', name,
                                  final.STATUS_SKIPPED)
