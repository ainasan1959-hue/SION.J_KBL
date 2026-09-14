// KBL Service Worker — プッシュ通知の受信・表示を担当

self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener('push', (event) => {
  let data = { title: 'KBL', body: '新しいお知らせがあります' };
  try {
    if (event.data) data = event.data.json();
  } catch (e) {
    // JSON以外で届いた場合はデフォルト文言のまま表示
  }

  const options = {
    body: data.body,
    icon: 'icon-192.png',
    badge: 'icon-192.png'
  };

  event.waitUntil(self.registration.showNotification(data.title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({ type: 'window' }).then((clientList) => {
      for (const client of clientList) {
        if ('focus' in client) return client.focus();
      }
      if (self.clients.openWindow) return self.clients.openWindow('./index.html');
    })
  );
});
