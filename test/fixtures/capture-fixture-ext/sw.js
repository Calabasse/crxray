chrome.storage.local.set({ swStarted: true, token: 'should-not-redact-in-storage-value-test' });

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg && msg.type === 'PING') {
    chrome.storage.local.set({ lastPing: Date.now(), apiKey: 'secret-should-be-redacted' });
    sendResponse({ type: 'PONG' });
  }
});
