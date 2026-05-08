import re

class TargetHandler:
    def normalize(self, target):
        target = target.strip()

        # Remove protocol if exists
        target = re.sub(r'^https?://', '', target)

        return target

    def is_ip(self, target):
        return re.match(r'\d+\.\d+\.\d+\.\d+', target) is not None