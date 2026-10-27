import sys
import types
import os

# Stub substrate2 before any project module is imported
_m = types.ModuleType("substrate2")
_pb = types.ModuleType("substrate2.policy_binding")
_pb.policy_ref = lambda doc: "stub-ref"
_pb.policy_bound_ref = lambda s, p: "stub-bound"
_m.policy_binding = _pb
sys.modules.setdefault("substrate2", _m)
sys.modules.setdefault("substrate2.policy_binding", _pb)

os.environ.setdefault("AHUB_ADMIN_TOKEN", "XJdmrAM-n6p93hUjCBgYXEvKrLArLxX2tS2yM9NgSc8")
os.environ.setdefault("AHUB_AUDIT_KEY",   "pEUmW-wSkk4QvUj68EXWsaGwHImZHEuO-PpqYscW8dM")
os.environ.setdefault("AHUB_REGISTRATION_TOKEN", "14HparfAiih7jrNGmYBQ6j_UrGdLo5QXRGeSGDDeLzw")
os.environ.setdefault("AHUB_REGISTRATION_NAME", "test-addon")
