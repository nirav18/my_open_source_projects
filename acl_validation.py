from pybatfish.client.commands import *
from pybatfish.question import bfq
from pybatfish.question.question import load_questions
from pybatfish.datamodel.flow import (HeaderConstraints,PathConstraints)

load_questions()


# Check if a representative host can reach the DNS server
dns_flow = HeaderConstraints(srcIps="192.168.0.1",
                             dstIps="192.168.0.1",
                             applications=["www"])
answer = bfq.testFilters(headers=dns_flow,
                         nodes="rtr-with-acl",
                         filters="acl_in").answer()
show(answer.frame())