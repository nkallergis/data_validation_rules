import re
from nautobot.extras.models.tags import Tag
from nautobot_data_validation_engine.custom_validators import DataComplianceRule, ComplianceError

class DeviceDataComplianceRules(DataComplianceRule):
    model = "dcim.device"
    enforce = True

    # Checks if a device name contains any special characters other than a dash (-), underscore (_), or period (.) using regex
    def audit_device_name_chars(self):
        if not re.match("^[a-zA-Z0-9\-_.]+$", self.context["object"].name):
            raise ComplianceError({"name": "Device name contains unallowed special characters."})

    # Checks if two IKE-related tags are attached to the device
    def audit_device_tags(self):
        ike_tags = Tag.objects.filter(name__startswith='IKE')
        applied_ike_tags = 0
        for ike_tag in ike_tags:
            if ike_tag in self.context["object"].tags.all():
                applied_ike_tags += 1
        if applied_ike_tags > 1:
            raise ComplianceError({"tags": "Device tags contain multiple IKE versions."})

    def audit(self):
        messages = {}
        for fn in [self.audit_device_name_chars, self.audit_device_tags]:
            try:
                fn()
            except ComplianceError as ex:
                messages.update(ex.message_dict)
        if messages:
            raise ComplianceError(messages)
