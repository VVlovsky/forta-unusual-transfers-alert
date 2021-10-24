import eth_abi
import forta_agent
from Crypto.Hash import keccak
from forta_agent import Finding, FindingType, FindingSeverity
from src.constants import COMPTROLLER_ADDRESS, TRANSACTION_SIZE_TH, TRANSFER, COMP_ADDRESS, \
    TRANSACTION_SIZE_TH_HIGH, TRANSACTION_SIZE_TH_CRITICAL
from eth_utils import decode_hex
from forta_agent import transaction_event


# This is the monkey patch which resolves the issue with Error: python: module 'sha3' has no attribute 'keccak_256'
def patch_keccak(val):
    hash = keccak.new(digest_bits=256)
    hash.update(bytes(val, encoding='utf-8'))
    return f'0x{hash.hexdigest()}'


transaction_event.keccak256 = patch_keccak


def check_amount_out(transaction_event):
    events_list = transaction_event.filter_event(TRANSFER, COMP_ADDRESS)
    for event in events_list:
        # event Transfer(address indexed from, address indexed to, uint256 amount);
        data = eth_abi.decode_abi(["uint256"], decode_hex(event.data))
        topics = list(map(lambda x: eth_abi.decode_abi(["address"], decode_hex(x)), event.topics[1:]))
        message = {
            'from': topics[0][0],
            'to': topics[1][0],
            'amount': data[0]
        }
        if message['from'] == COMPTROLLER_ADDRESS and message['amount'] > TRANSACTION_SIZE_TH:
            return True, message['amount']
    return False, 0


def handle_transaction(transaction_event: forta_agent.transaction_event.TransactionEvent):
    findings = []
    need_to_be_alerted, amount = check_amount_out(transaction_event)
    if need_to_be_alerted:
        findings.append(Finding({
            'name': 'Large Transfer Out of Comptroller Contract',
            'description': f'{int(amount) / 10 ** 18} COMP were transferred out of Comptroller Contract',
            'alert_id': 'COMP_LRG_OUT',
            'type': FindingType.Suspicious,
            'severity': get_severity(amount),
            'metadata': {
                'out': amount
            }
        }))

    return findings


def get_severity(amount):
    if amount > TRANSACTION_SIZE_TH_CRITICAL:
        return FindingSeverity.Critical
    elif amount > TRANSACTION_SIZE_TH_HIGH:
        return FindingSeverity.High
    else:
        return FindingSeverity.Medium
