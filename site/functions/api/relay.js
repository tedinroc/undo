import { makeRelay } from '../_relay/handler.mjs';

export const onRequest = ({ request, env }) => makeRelay(env)(request);
