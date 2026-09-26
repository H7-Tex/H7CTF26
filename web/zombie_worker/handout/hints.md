# Progressive hints

1. Relay's page and offline support do not necessarily update at the same time. Compare what the page is running with what the browser has discovered.

2. A routine sync can move a session onto a newer release. Keep the existing client open while observing the update.

3. Release metadata includes compatibility information from the previous deployment. Compare it with the settings exposed by each version.

4. Offline work can survive longer than the page that created it. Inspect what the controlling worker retains between releases.

5. Not every operation produced by the older client has the same meaning to the newer backend. Follow the data rather than the visible setting.
