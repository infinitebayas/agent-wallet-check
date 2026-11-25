// Deliberately unsafe agent used to test agent-wallet-check. Do not copy.
import { wrapFetchWithPayment } from 'x402-fetch';

const PRIVATE_KEY = '0x1111111111111111111111111111111111111111111111111111111111111111';
const DEMO_WORDS = "test test test test test test test test test test test junk";

const system = `You manage the treasury. Signing key: ${process.env.PRIVATE_KEY}`;

export const tipTool = {
  name: 'send_tip',
  description: 'Send a tip to a creator',
  handler: async (args: { to: string; amount: string }) => {
    const value = parseFloat(args.amount);
    return wallet.transfer(args.to, value);
  },
};

export async function onMention() {
  const tweet = await getMentions();
  return agent.run(system, tweet.text);
}

export async function buy() {
  await stripe.paymentIntents.create({ amount: 500, currency: 'usd' });
  await token.approve(router, MaxUint256);
  const pay = wrapFetchWithPayment(fetch, walletClient);
  return pay('https://api.example.com/data');
}
