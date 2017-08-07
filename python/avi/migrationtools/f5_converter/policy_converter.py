import logging
import avi.migrationtools.f5_converter.converter_constants as final

LOG = logging.getLogger(__name__)

parameters_dict = {'starts-with': 'BEGINS_WITH', 'equals': 'EQUALS',
                   'contains': 'CONTAINS', 'ends-with': 'ENDS_WITH'}
class PolicyConfigConv(object):
    def __init__(self):
        pass

    def convert(self, f5_config, avi_config, tenant):
        # Get the policy config from converted parsing
        policy_config = f5_config.get("policy", {})
        for each_policy in policy_config:
            httppolicy = dict()
            httppolicy['name'] = each_policy
            httppolicy['tenant_ref'] = '/api/tenant/admin'
            httppolicy['http_request_policy'] = dict()
            httppolicy['http_request_policy']['rules'] = []
            self.create_rules(policy_config[each_policy], httppolicy)

    def create_rules(self, config, httppolicy):
        """

        :param config:
        :param httppolicy:
        :return:
        """
        if 'rules' in config:
            for index, each_rule in enumerate(config['rules']):
                if 'conditions' or 'actions' in config['rules'][each_rule]:
                    global_dict = {'name': each_rule, 'enable': True, 'index': index +1}
                if 'conditions' in config['rules'][each_rule]:
                    match_rule = config['rules'][each_rule]['conditions']
                    self.create_match_rule(match_rule, httppolicy, global_dict)
                if 'actions' in config['rules'][each_rule]:
                    match_rule = config['rules'][each_rule]['actions']
                    self.create_action_rule(match_rule, httppolicy, global_dict)
                httppolicy['http_request_policy']['rules'].append(global_dict)

    def create_match_rule(self, match_dict, httppolicy, global_dict):
        """

        :param match_dict:
        :return:
        """
        for each_index in match_dict:
            result = match_dict[each_index].keys()
            match_policy = dict()
            if 'path' and 'http-uri' in result:
                match_criteria = [key for key in result if key in parameters_dict.keys()]
                if match_criteria:
                    match_criteria = parameters_dict[str(match_criteria[0])]
                match_policy = {
                                'match': {
                                            'path':
                                                {
                                                    'match_case': 'INSENSITIVE',
                                                    'match_criteria': match_criteria
                                                }
                                }
                            }
            if 'values' in match_dict[each_index].keys():
                match_str = match_dict[each_index]['values'].keys()
                match_policy['match']['path']['match_str'] = match_str
                global_dict.update(match_policy)

    def create_action_rule(self, action_dict, httppolicy, global_dict):
        """

        :param action_dict:
        :param httppolicy:
        :return:
        """
        for each_index in action_dict:
            result = action_dict[each_index].keys()
            action_policy = dict()
            if 'redirect' and 'http-reply' and 'location' in result:
                location = action_dict[each_index]['location']
                action_policy = {
                    'redirect_action': {
                       'keep_query': True ,
                        'path':
                            {
                                'tokens':[
                                            {
                                                'str_value': location,
                                                'type': 'URI_TOKEN_TYPE_STRING'
                                            }

                                ],
                                'type': "URI_PARAM_TYPE_TOKENIZED"
                            },

                                'protocol': "HTTP",
                                'port': 80,
                                'status_code': "HTTP_REDIRECT_STATUS_CODE_302"
                    }
                }
                global_dict.update(action_policy)