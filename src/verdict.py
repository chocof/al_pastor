DEFAULT_ACTION = 'allow'


class Verdict:
    def __init__(self, data=None):
        # when it was received
        self.seconds = data["seconds"] if "seconds" in data else 0
        # possible actions (log, pass, activate, dynamic, allow)
        self.action = data["action"] if "action" in data else DEFAULT_ACTION
        # The classtype keyword is used to categorize a rule as
        # detecting an attack that is part of a more general
        # type of attack class
        self.threat_class = data["class"] if "class" in data else ""
        # Informative message regarding the packet
        self.msg = data["msg"] if "msg" in data else ""
        # Used for identification
        self.pac_id = data["pkt_num"] if "pkt_num" in data else 0
        # how important is it
        self.priority = data["priority"] if "priority" in data else 0

    def get_packet_id(self,):
        return self.pac_id

    def get_priority(self,):
        return self.priority

    def is_important(self,):
        return self.priority > 0

    def get_msg(self, ):
        return self.msg
    def get_threat_class(self, ):
        return self.threat_class

    def __str__(self):
        return "![{}] ACTION: {}/MSG: {}\n"\
            .format(self.priority, self.action, self.msg)
