import re
from nautobot_data_validation_engine.custom_validators import DataComplianceRule, ComplianceError

class DeviceDataComplianceRules(DataComplianceRule):
    model = "dcim.device"
    enforce = False

    # Checks if a device name contains any special characters other than a dash (-), underscore (_), or period (.) using regex
    def audit_device_name_chars(self):
        if not re.match("^[a-zA-Z0-9\-_.]+$", self.context["object"].name):
            raise ComplianceError({"name": "Device name contains unallowed special characters."})

    # Checks if a device is not assigned to a rack
    def audit_device_rack(self):
        if not self.context["object"].rack:
            raise ComplianceError({"rack": "Device should be assigned to a rack."})

    def audit(self):
        messages = {}
        for fn in [self.audit_device_name_chars, self.audit_device_rack]:
            try:
                fn()
            except ComplianceError as ex:
                messages.update(ex.message_dict)
        if messages:
            raise ComplianceError(messages)