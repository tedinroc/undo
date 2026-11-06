// The landing page. It creates nothing and calls no relay: a visitor who never taps costs nothing. All it reads is
// the page's own config, to put this deployment's chip and contract into the status line. Everything else is in
// the HTML, so the page reads the same with scripts off.
import { loadConfig } from '/site/lib/index.mjs';

const $ = (id) => document.getElementById(id);

/** The film slot keeps its poster when the film file is missing or will not play: that is the slot's normal state. */
function watchFilm() {
  const slot = $('film-slot');
  const video = $('film');
  const source = $('film-source');
  if (!slot || !video || !source) return;
  const missing = () => {
    slot.dataset.film = 'missing';
  };
  source.addEventListener('error', missing);
  video.addEventListener('error', missing);
  video.addEventListener('playing', () => {
    slot.dataset.film = 'playing';
  });
  // An error that fired before this module ran leaves its mark here.
  if (video.networkState === HTMLMediaElement.NETWORK_NO_SOURCE) missing();
}

function curlLine(config) {
  const args = JSON.stringify({
    jsonrpc: '2.0', id: 'u', method: 'query',
    params: { request_type: 'call_function', finality: 'final', account_id: config.contract, method_name: 'status', args_base64: 'e30=' },
  });
  return `curl -s ${config.rpc[0]} -H 'content-type: application/json' -d '${args}' | python3 -c 'import sys,json;print(bytes(json.load(sys.stdin)["result"]["result"]).decode())'`;
}

async function main() {
  watchFilm();
  let config;
  try {
    config = await loadConfig();
  } catch {
    // The static text stands: the chip the HTML drew, and the status line with <CONTRACT> in it.
    document.documentElement.dataset.config = 'none';
    return;
  }
  $('chip').textContent = config.labels.chip;
  $('foot-chip').textContent = config.labels.chip;
  if (!config.contract.startsWith('FILL-AT-DEPLOY')) {
    $('curl').textContent = curlLine(config);
    $('curl-note').textContent = `${config.labels.near} contract ${config.contract}. It answers {ok, lines}: the instance's state in plain words.`;
  }
  document.documentElement.dataset.config = config.mode;
}

main();
