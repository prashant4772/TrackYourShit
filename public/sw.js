self.addEventListener('push', event => {
  const data = event.data?.json() || { title: 'tracl', body: 'Time to study!' };
  event.waitUntil(
    self.registration.showNotification(data.title || 'tracl', {
      body: data.body || '',
      icon: '/icon-192.png',
      badge: '/icon-192.png',
      tag: data.tag || 'tracl',
      renotify: true,
      requireInteraction: false
    })
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(list => {
      for (const c of list) {
        if ('focus' in c) return c.focus();
      }
      if (clients.openWindow) return clients.openWindow('/');
    })
  );
});
