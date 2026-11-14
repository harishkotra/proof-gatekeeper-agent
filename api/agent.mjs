import { handle } from '../src/handler.mjs';

export const config = { api: { bodyParser: false }, maxDuration: 60 };

export default async function (req, res) {
  return handle(req, res);
}
