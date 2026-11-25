# Deliberately unsafe agent used to test agent-wallet-check. Do not copy.
def send_tip(to: str, amount: str):
    value = float(amount)
    return wallet.transfer(to, value)
