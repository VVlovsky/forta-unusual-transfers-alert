from forta_agent import FindingSeverity, FindingType, create_transaction_event
from src.agent import handle_transaction, patch_keccak
from src.constants import COMPTROLLER_ADDRESS, TRANSACTION_SIZE_TH, TRANSFER, COMP_ADDRESS
import eth_abi
from eth_utils import encode_hex


def generate_keccak256(sign: str) -> str:
    hash = patch_keccak(sign)
    return hash


class TestHighTransfersAgent:

    def test_returns_empty_findings_if_comp_below_threshold(self):
        data = eth_abi.encode_abi(["uint256"], [TRANSACTION_SIZE_TH - 1])
        data = encode_hex(data)
        hash = generate_keccak256(TRANSFER)
        from_ = eth_abi.encode_abi(["address"], [COMPTROLLER_ADDRESS])
        from_ = encode_hex(from_)
        to = eth_abi.encode_abi(["address"], [COMPTROLLER_ADDRESS])
        to = encode_hex(to)
        topics = [hash, from_, to]

        tx_event = create_transaction_event({
            'receipt': {
                'logs': [{'topics': topics,
                          'data': data,
                          'address': COMP_ADDRESS}]}
        })

        findings = handle_transaction(tx_event)

        assert len(findings) == 0

    def test_returns_finding_if_comp_above_threshold(self):
        data = eth_abi.encode_abi(["uint256"], [TRANSACTION_SIZE_TH + 1])
        data = encode_hex(data)
        hash = generate_keccak256(TRANSFER)
        from_ = eth_abi.encode_abi(["address"], [COMPTROLLER_ADDRESS])
        from_ = encode_hex(from_)
        to = eth_abi.encode_abi(["address"], [COMPTROLLER_ADDRESS])
        to = encode_hex(to)
        topics = [hash, from_, to]

        tx_event = create_transaction_event({
            'receipt': {
                'logs': [{'topics': topics,
                          'data': data,
                          'address': COMP_ADDRESS}]}
        })

        findings = handle_transaction(tx_event)
        for finding in findings:
            assert finding.alert_id == 'COMP_LRG_OUT'
            assert finding.description == '300.0 COMP were transferred out of Comptroller Contract'
            assert finding.metadata == {'out': 300000000000000000001}
            assert finding.name == 'Large Transfer Out of Comptroller Contract'
            assert finding.severity == FindingSeverity.Medium
            assert finding.type == FindingType.Suspicious
