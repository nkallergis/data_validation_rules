import re
from nautobot_data_validation_engine.custom_validators import DataComplianceRule, ComplianceError

class PrefixDataComplianceRules(DataComplianceRule):
    model = "ipam.prefix"
    enforce = True

    # Checks whether the prefix mask is smaller than /16
    def audit_prefix_mask(self):
        if self.context["object"].prefix_length < 16:
            raise ComplianceError({"prefix_length": "Prefix length cannot be less than 16."})

    # Checks whether a prefix has been assigned to more than a single location
    def audit_prefix_locations(self):
        if self.context["object"].locations.count() > 1:
            raise ComplianceError({"locations": "Cannot assign to more than one locations."})

    def audit(self):
        messages = {}
        for fn in [self.audit_prefix_mask, self.audit_prefix_locations]:
            try:
                fn()
            except ComplianceError as ex:
                messages.update(ex.message_dict)
        if messages:
            raise ComplianceError(messages)
