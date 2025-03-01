const { v4: uuidv4 } = require('uuid');

// https://developers.cloudflare.com/workers/examples/websockets/

// Function to handle notifications
async function notification(method, params) {
  console.log('method:', method);
  console.log('params:');
  console.log(JSON.stringify(params, null, '  '));

  /* ENTER YOUR INTEGRATION CODE HERE */
  /* method contains the event type e.g. vulnerability-created */
  /* params contains the event body e.g. JSON object with timestamp & vulnerability details */
}

// Function to load the replay timestamp from KV
async function loadReplayTimestamp(env) {
  try {
    const timestamp = await env.WORKER_STATE.get('replay_timestamp');
    if (timestamp) {
      // console.log('Loaded replay timestamp from KV:', timestamp);
      return timestamp;
    } else if (env.FROM) {
      // console.log('Loaded replay timestamp from environment:', env.FROM);
      return env.FROM;
    } else {
      const now = new Date().toISOString();
      // console.log('No stored timestamp found, using current time:', now);
      return now;
    }
  } catch (err) {
    console.error('Error loading timestamp:', err);
    const now = new Date().toISOString();
    // console.log('Using current time as fallback:', now);
    return now;
  }
}

// Function to store the replay timestamp in KV
async function storeReplayTimestamp(env, timestamp) {
  try {
    await env.WORKER_STATE.put('replay_timestamp', timestamp);
    // console.log('Stored replay timestamp in KV:', timestamp);
  } catch (err) {
    console.error('Error storing timestamp:', err);
  }
}

// Connect to WebSocket and handle the connection
async function connectToWebSocket(env, ctx) {
  // Validate required environment variables
  if (!env.HOSTNAME) {
    throw new Error('Environment variable HOSTNAME is undefined');
  }
  if (!env.EVENTS) {
    throw new Error('Environment variable EVENTS is undefined');
  }
  if (!env.X_SSAPI_KEY) {
    throw new Error('Environment variable X_SSAPI_KEY is undefined');
  }

  const port = env.PORT || 443;
  // Change from wss:// to https:// for Cloudflare Workers
  const url = `https://${env.HOSTNAME}${port !== 443 ? `:${port}` : ''}/api/ss/events`;

  // Using Cloudflare's recommended approach for WebSocket clients
  try {
    // Make a fetch request with Upgrade: websocket header
    const resp = await fetch(url, {
      headers: {
        'Upgrade': 'websocket',
        'Connection': 'Upgrade',
        'X-SSAPI-KEY': env.X_SSAPI_KEY
      },
    });
    const headers = {};
    for (const [key, value] of resp.headers.entries()) {
      headers[key] = value;
    }
    const ws = resp.webSocket;
    if (!ws) {
      console.error('WebSocket handshake failed. Response body:');
      const text = await resp.text();
      console.error(text);
      throw new Error(`Server didn't accept WebSocket connection. Status: ${resp.status}`);
    }
    // Accept the WebSocket connection
    ws.accept();

    // Set up event listeners
    setupWebSocketHandlers(ws, env, ctx);
    await subscribe(ws, env);
    return ws;
  } catch (error) {
    console.error('Error establishing WebSocket connection:', error);
    throw error;
  }
}

// Set up WebSocket event handlers
function setupWebSocketHandlers(ws, env, ctx) {
  // Store pending requests
  ws.pendingRequests = {};

  // Set up heartbeat mechanism
  let heartbeatInterval;
  let heartbeatTimeout;

  function setupHeartbeat() {
    clearInterval(heartbeatInterval);
    clearTimeout(heartbeatTimeout);

    // Send heartbeat every 25 seconds
    heartbeatInterval = setInterval(() => {
      try {
        // Check if the WebSocket is open by trying to send a small ping
        // We don't need to send an actual heartbeat as the server will send them
      } catch (error) {
        console.error('Error in heartbeat check:', error);
        clearInterval(heartbeatInterval);
        clearTimeout(heartbeatTimeout);
        try {
          ws.close(1000, 'Connection error during heartbeat check');
        } catch (closeError) {
          console.error('Error closing WebSocket:', closeError);
        }
      }
    }, 25000);

    // Set timeout for heartbeat response
    heartbeatTimeout = setTimeout(() => {
      // console.log('Heartbeat timeout, closing connection');
      try {
        ws.close(1000, 'Heartbeat timeout');
      } catch (error) {
        console.error('Error closing WebSocket on timeout:', error);
      }
    }, 30000 + 1000);
  }

  // Set up message handler
  ws.addEventListener('message', async (event) => {
    try {
      const payload = JSON.parse(event.data);
      if (payload.jsonrpc === '2.0') {
        if ('method' in payload && !('id' in payload)) {
          if (payload.params && payload.params.timestamp) {
            await storeReplayTimestamp(env, payload.params.timestamp);
          }
          await notification(payload.method, payload.params);
        }
        else if ('method' in payload && 'id' in payload) {
          if (payload.method === 'heartbeat') {
            ws.send(JSON.stringify({
              jsonrpc: "2.0",
              result: new Date().toISOString(),
              id: payload.id
            }));
            // Reset heartbeat timers
            setupHeartbeat();
          }
        }
        else if ('result' in payload && 'id' in payload) {
          if (payload.id in ws.pendingRequests) {
            clearTimeout(ws.pendingRequests[payload.id].timeout);
            ws.pendingRequests[payload.id].success(payload.result, payload.id);
          }
        }
        else if ('error' in payload && 'id' in payload) {
          if (payload.id in ws.pendingRequests) {
            clearTimeout(ws.pendingRequests[payload.id].timeout);
            ws.pendingRequests[payload.id].failure(payload.error, payload.id);
          }
        }
        else {
          console.error('Unsupported message format');
        }
      }
    } catch (err) {
      console.error('Error parsing message:', err);
    }
  });

  // Set up error handler
  ws.addEventListener('error', (error) => {
    console.error('WebSocket error:', error);
  });

  // Set up close handler
  ws.addEventListener('close', (event) => {
    // console.log(`WebSocket closed with code ${event.code}: ${event.reason}`);
    clearInterval(heartbeatInterval);
    clearTimeout(heartbeatTimeout);
    // console.log('Connection will be re-established on next scheduled run');
  });
  // Initial heartbeat setup
  setupHeartbeat();
}

// Subscribe to events
async function subscribe(ws, env) {
  const events = env.EVENTS.split(',').map(x => x.trim());
  const timestamp = await loadReplayTimestamp(env);
  const request = {
    jsonrpc: "2.0",
    method: "subscribe",
    params: {
      events: events,
      from: timestamp
    },
    id: uuidv4().toString()
  };

  return new Promise((resolve, reject) => {
    const timeoutId = setTimeout(() => {
      delete ws.pendingRequests[request.id];
      reject(new Error(`Subscription request ${request.id} timed out`));
    }, 5000);

    ws.pendingRequests[request.id] = {
      request: request,
      success: (result, id) => {
        // console.log('Subscribed to the following events:', result);
        delete ws.pendingRequests[request.id];
        resolve(result);
      },
      failure: (error, id) => {
        // console.log(`Subscription request ${id} failed:`, error);
        delete ws.pendingRequests[request.id];
        reject(new Error(`Subscription failed: ${JSON.stringify(error)}`));
      },
      timeout: timeoutId
    };
    ws.send(JSON.stringify(request));
  });
}

// Cloudflare Worker entry point
export default {
  async fetch(request, env, ctx) {
    return new Response("AttackForge Enterprise Self-Service Events API Worker is running", {
      headers: { "Content-Type": "text/plain" }
    });
  },

  async scheduled(event, env, ctx) {
    try {
      const ws = await connectToWebSocket(env, ctx);

      // console.log("WebSocket connection established, setting up waitUntil...");
      // Use waitUntil to keep the worker running for the duration of the WebSocket connection
      ctx.waitUntil(new Promise((resolve) => {
        ws.addEventListener('close', (event) => {
          // console.log(`WebSocket connection closed with code ${event?.code || 'unknown'}: ${event?.reason || 'no reason'}`);
          // console.log('Resolving waitUntil promise');
          resolve();
        });

        // Also set a timeout to ensure the promise resolves even if close event doesn't fire
        setTimeout(() => {
          // console.log('Maximum execution time reached, resolving waitUntil promise');
          try {
            ws.close(1000, 'Maximum execution time reached');
          } catch (error) {
            console.error('Error closing WebSocket on timeout:', error);
          }
          resolve();
        }, 25000);
      }));

      return new Response("WebSocket connection established", { status: 200 });
    } catch (error) {
      console.error('Failed to establish WebSocket connection:', error);

      // Create a detailed error response
      const errorDetails = {
        message: error.message,
        stack: error.stack,
        timestamp: new Date().toISOString()
      };

      console.error('Error details:', JSON.stringify(errorDetails, null, 2));

      return new Response(
        `Failed to establish WebSocket connection: ${error.message}`,
        {
          status: 500,
          headers: { "Content-Type": "text/plain" }
        }
      );
    }
  }
};

