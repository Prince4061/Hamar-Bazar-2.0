const CACHE_NAME = 'hamar-bazar-cache-v8';
const ASSETS_TO_CACHE = [
  '/static/offline.html'
];

// Install Event
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      console.log('[Service Worker] Pre-caching static assets');
      // Use catch to prevent single asset failures from breaking the installation
      return Promise.allSettled(
        ASSETS_TO_CACHE.map(url => {
          return cache.add(url).catch(err => {
            console.warn(`[Service Worker] Failed to cache: ${url}`, err);
          });
        })
      );
    })
  );
  self.skipWaiting();
});

// Activate Event
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cache) => {
          if (cache !== CACHE_NAME) {
            console.log('[Service Worker] Clearing old cache');
            return caches.delete(cache);
          }
        })
      );
    })
  );
  self.clients.claim();
});

// Fetch Event (Network-First with Cache Fallback for assets, Network-Only for dynamic APIs & HTML routes)
self.addEventListener('fetch', (event) => {
  const requestUrl = new URL(event.request.url);

  // Dynamic routes, HTML pages, API requests, and external URLs should not be cached (Network-only)
  if (
    event.request.method !== 'GET' ||
    requestUrl.origin !== self.location.origin ||
    requestUrl.pathname.startsWith('/api/') ||
    requestUrl.pathname.startsWith('/session/') ||
    requestUrl.pathname === '/admin' ||
    requestUrl.pathname === '/customer' ||
    requestUrl.pathname === '/vendor' ||
    requestUrl.pathname === '/delivery' ||
    requestUrl.pathname === '/' ||
    requestUrl.pathname === '/login' ||
    requestUrl.pathname === '/staff-login'
  ) {
    event.respondWith(fetch(event.request));
    return;
  }

  // Serve static assets from cache first, fall back to network
  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      if (cachedResponse) {
        // Fetch in background to update cache (stale-while-revalidate)
        fetch(event.request).then((networkResponse) => {
          if (networkResponse.status === 200) {
            caches.open(CACHE_NAME).then((cache) => {
              cache.put(event.request, networkResponse);
            });
          }
        }).catch(() => {/* Ignore network errors during background fetch */});
        
        return cachedResponse;
      }

      return fetch(event.request).catch(() => {
        // Offline Fallback for HTML pages
        if (event.request.headers.get('accept') && event.request.headers.get('accept').includes('text/html')) {
          return caches.match('/static/offline.html');
        }
      });
    })
  );
});
