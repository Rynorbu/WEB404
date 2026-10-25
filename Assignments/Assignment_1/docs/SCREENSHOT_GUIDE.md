# Screenshot Guide

This guide tells you exactly which screenshots to take for the report (`README.md`), how to take each one, what should be visible, and the file name to save it as.

Save every screenshot in **`docs/screenshots/`** using the **exact file name** given. The README already links to these names, so each image appears in the report as soon as you save it.

---

## 0. Before you start (one-time setup)

1. Open a terminal in the `Assignment_1` folder (in VS Code: **Terminal → New Terminal**).
2. Install dependencies and generate the sample attack files:
   ```powershell
   npm install
   npm run samples
   ```
   This creates a `samples/` folder with 12 test files (2 safe, 10 malicious). The "malicious" files are **harmless imitations**. They have the structure of real attacks but do nothing.
   > If Windows Defender deletes `03-shell.php`, `05-fake-image.jpg` or `06-polyglot.png`, run `npm run samples` again, or add the `samples` folder as a Defender exclusion. Defender flagging them is good evidence for your report that these look like attacks.
3. Start with a clean state (no previously uploaded files):
   ```powershell
   Remove-Item -Recurse -Force uploads, logs -ErrorAction SilentlyContinue
   ```
4. Start the server and leave this terminal running:
   ```powershell
   npm start
   ```
5. Open **Google Chrome** (or Edge) at **http://localhost:3000**.
6. Open a **second terminal** (click **+** in the VS Code terminal panel) for the `curl` commands below.

### How to take screenshots on Windows
- **Win + Shift + S**: select an area, then paste it into Paint and save as PNG. Or click the notification and save from Snipping Tool.
- For a full web page, Chrome can do it: press **F12**, then **Ctrl + Shift + P**, type `screenshot`, and choose **Capture full size screenshot**.
- Keep the browser at normal zoom (100%) and maximise the window so the screenshots look consistent.

### Important: use `curl.exe`, not `curl`
In Windows PowerShell, `curl` is an alias for a different command. Always type **`curl.exe`**.

---

## Part A: Application walkthrough

| # | File name | What to do | What must be visible |
|---|-----------|------------|----------------------|
| 1 | `fig01-home.png` | Open http://localhost:3000 in light mode. Take a full-page screenshot. | Header, "Upload files safely" title, upload card, "How we protect you" panel, empty "Your files" list |
| 2 | `fig02-dark-mode.png` | Click the **sun/moon button** (top right) to switch to dark mode. Screenshot. Click it again to return to light mode afterwards. | The same page in dark mode |
| 3 | `fig03-mobile.png` | Press **F12**, then click the **phone/tablet icon** (Toggle device toolbar, **Ctrl + Shift + M**). Choose **iPhone 12 Pro** from the top dropdown. Screenshot only the phone view. Close DevTools afterwards. | Single-column mobile layout |
| 4 | `fig04-file-selected.png` | Click **Click to browse** and choose `samples/01-valid-image.png`. **Do not upload yet.** Screenshot the upload card. | Image thumbnail preview, file name, size, "Ready to upload", enabled **Upload securely** button |
| 5 | `fig05-upload-success.png` | Click **Upload securely**. Screenshot immediately while the green notification is still showing (it disappears after 5 seconds). | Green "Upload complete" panel with the 6 ticked security checks, the toast at the bottom right, and the file in the list |
| 6 | `fig06-file-list.png` | Upload `samples/02-valid-document.pdf` as well. Then type `doc` in the **Search files** box. Screenshot the "Your files" card. Clear the search afterwards. | File list with type badges, size, time, "Verified" tag, filtered by search |
| 7 | `fig07-download.png` | Clear the search and click **Download** next to the PNG. Screenshot the browser's download popup or bar showing the file was downloaded. | Download of `01-valid-image.png` |
| 8 | `fig08-uploads-folder.png` | In File Explorer (or the VS Code sidebar), open the `uploads` folder. Screenshot it. | Files stored with **random UUID names** (e.g. `8b73cd4c-….png`) instead of the original names, plus `index.json` |

---

## Part B: Attack demonstrations

For each attack, take the screenshot(s) listed. The text after `→` is the exact message you should see.

### B1. Web shell upload (`.php`)

| # | File name | What to do |
|---|-----------|------------|
| 9 | `fig09-php-browser.png` | In the browser, choose `samples/03-shell.php`. Screenshot the red message. → *"".php" files aren't allowed. Choose a PNG, JPG, GIF or PDF."* (this is the browser check) |
| 10 | `fig10-php-curl.png` | An attacker can skip the browser entirely. In the second terminal run the command below and screenshot the command together with its output. → `File type ".php" is not allowed…` **[HTTP 400]** |

```powershell
curl.exe -s -w "  [HTTP %{http_code}]`n" -F "file=@samples/03-shell.php;type=application/x-php" http://localhost:3000/api/upload
```

### B2. Double extension (`shell.php.jpg`)

| # | File name | What to do |
|---|-----------|------------|
| 11 | `fig11-double-extension.png` | In the browser, choose `samples/04-shell.php.jpg` and click **Upload securely**. Screenshot the upload card. → *"File name has a disallowed double extension."* |

### B3. Disguised script (PHP renamed to `.jpg`)

| # | File name | What to do |
|---|-----------|------------|
| 12 | `fig12-magic-bytes-hex.png` | In the second terminal run the two commands below. Screenshot both outputs together. They show that a real PNG starts with `89 50 4E 47` while the fake JPG starts with `3C 3F 70 68` (`<?ph`). |
| 13 | `fig13-fake-image.png` | In the browser, upload `samples/05-fake-image.jpg`. Screenshot. → *"File content does not match its extension."* |

```powershell
Format-Hex samples\01-valid-image.png | Select-Object -First 1
Format-Hex samples\05-fake-image.jpg  | Select-Object -First 2
```

### B4. Polyglot image (valid PNG with PHP code appended)

| # | File name | What to do |
|---|-----------|------------|
| 14 | `fig14-polyglot-hex.png` | Run the command below and screenshot it. The right-hand column shows the PHP code hidden **after** the end of the real image (`IEND`). |
| 15 | `fig15-polyglot.png` | In the browser, upload `samples/06-polyglot.png`. Note that the preview shows a normal-looking image. Screenshot after uploading. → *"File structure is invalid or has data appended."* |

```powershell
Format-Hex samples\06-polyglot.png | Select-Object -Last 6
```

### B5. Stored XSS via SVG / HTML

| # | File name | What to do |
|---|-----------|------------|
| 16 | `fig16-xss-curl.png` | Run both commands below and screenshot. → both return `File type ".svg"/".html" is not allowed` **[HTTP 400]** |

```powershell
Get-Content samples\07-xss.svg
curl.exe -s -w "  [HTTP %{http_code}]`n" -F "file=@samples/07-xss.svg;type=image/svg+xml" http://localhost:3000/api/upload
curl.exe -s -w "  [HTTP %{http_code}]`n" -F "file=@samples/08-page.html;type=text/html" http://localhost:3000/api/upload
```

### B6. Malicious PDF (embedded JavaScript)

| # | File name | What to do |
|---|-----------|------------|
| 17 | `fig17-malicious-pdf.png` | In the browser, upload `samples/09-malicious.pdf`. Screenshot. → *"File contains potentially malicious content."* |

### B7. MIME type spoofing

| # | File name | What to do |
|---|-----------|------------|
| 18 | `fig18-mime-spoof.png` | Run the command below (a real PNG, but it claims to be HTML). Screenshot. → `File content type does not match its extension.` **[HTTP 400]** |

```powershell
curl.exe -s -w "  [HTTP %{http_code}]`n" -F "file=@samples/01-valid-image.png;type=text/html" http://localhost:3000/api/upload
```

### B8. Denial of service (oversized and empty files)

| # | File name | What to do |
|---|-----------|------------|
| 19 | `fig19-large-file.png` | Run the two commands below. Screenshot both outputs. → `File is too large. Maximum size is 5 MB.` **[HTTP 413]** and `The file is empty.` **[HTTP 400]** |

```powershell
curl.exe -s -w "  [HTTP %{http_code}]`n" -F "file=@samples/11-large-file.png;type=image/png" http://localhost:3000/api/upload
curl.exe -s -w "  [HTTP %{http_code}]`n" -F "file=@samples/12-empty.png;type=image/png" http://localhost:3000/api/upload
```

### B9. Path traversal

| # | File name | What to do |
|---|-----------|------------|
| 20 | `fig20-path-traversal-upload.png` | Run the first command below (the file name tries to escape the folder). Screenshot the output **and** the `uploads` folder showing it was saved inside it with a UUID name. → `"originalName":"evil.png"` **[HTTP 201]**. The `../../../` was removed and nothing was written outside `uploads/`. |
| 21 | `fig21-path-traversal-download.png` | In the browser address bar, open the two URLs below one at a time. Screenshot both results (or put them side by side). → `{"error":"Invalid file id."}` and a **404** page |

```powershell
curl.exe -s -w "  [HTTP %{http_code}]`n" -F "file=@samples/01-valid-image.png;type=image/png;filename=../../../evil.png" http://localhost:3000/api/upload
```
URLs for Figure 21:
- `http://localhost:3000/api/files/..%2F..%2Fpackage.json`
- `http://localhost:3000/uploads/` followed by a real file name from your `uploads` folder (e.g. `http://localhost:3000/uploads/8b73cd4c-c7a1-4914-ad34-9052162f727b.png`). This proves uploaded files cannot be opened directly.

### B10. Cross-Site Request Forgery (CSRF)

| # | File name | What to do |
|---|-----------|------------|
| 22 | `fig22-csrf.png` | Run the command below (pretends the request comes from another website). Screenshot. → `Cross-origin request rejected.` **[HTTP 403]** |

```powershell
curl.exe -s -w "  [HTTP %{http_code}]`n" -H "Origin: https://evil.example" -F "file=@samples/01-valid-image.png;type=image/png" http://localhost:3000/api/upload
```

### B11. Upload flooding (rate limiting)

The default limit is 20 uploads per 15 minutes. To show it quickly, restart the server with a limit of 3:

1. In the **server terminal**, press **Ctrl + C** to stop it, then run:
   ```powershell
   $env:RATE_LIMIT_MAX=3; npm start
   ```
2. In the second terminal run:
   ```powershell
   1..5 | ForEach-Object { curl.exe -s -w "  [HTTP %{http_code}]`n" -F "file=@samples/01-valid-image.png;type=image/png" http://localhost:3000/api/upload }
   ```
3. Screenshot the output as **`fig23-rate-limit.png`**. → the first 3 return **201**, then `Too many uploads. Please try again later.` **[HTTP 429]**
4. Restore the normal limit: press **Ctrl + C** in the server terminal, then run:
   ```powershell
   Remove-Item Env:RATE_LIMIT_MAX; npm start
   ```

---

## Part C: Evidence of the protections

| # | File name | What to do | What must be visible |
|---|-----------|------------|----------------------|
| 24 | `fig24-response-headers.png` | In the browser press **F12**, open the **Network** tab and tick **Preserve log**. Click **Download** on any file. Click the request named with the long UUID, open **Headers**, and scroll to **Response Headers**. Screenshot. | `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; sandbox`, `X-Frame-Options: DENY` |
| 25 | `fig25-security-log.png` | Open `logs/security.log` in VS Code. Screenshot several lines. | JSON lines with `upload-accepted` / `upload-rejected` and the reason (e.g. `double-extension`, `magic-bytes-mismatch`, `bad-trailer`) |
| 26 | `fig26-tests.png` | Stop the server (**Ctrl + C**) and run `npm test`. Screenshot the output (scroll up if needed, or take two screenshots). | All 26 tests with ✔, and `pass 26`, `fail 0` |

---

## Checklist

After you finish, `docs/screenshots/` should contain these 26 files:

```
fig01-home.png               fig14-polyglot-hex.png
fig02-dark-mode.png          fig15-polyglot.png
fig03-mobile.png             fig16-xss-curl.png
fig04-file-selected.png      fig17-malicious-pdf.png
fig05-upload-success.png     fig18-mime-spoof.png
fig06-file-list.png          fig19-large-file.png
fig07-download.png           fig20-path-traversal-upload.png
fig08-uploads-folder.png     fig21-path-traversal-download.png
fig09-php-browser.png        fig22-csrf.png
fig10-php-curl.png           fig23-rate-limit.png
fig11-double-extension.png   fig24-response-headers.png
fig12-magic-bytes-hex.png    fig25-security-log.png
fig13-fake-image.png         fig26-tests.png
```

Then open `README.md` in VS Code and press **Ctrl + Shift + V** to preview the report with all images. Fix any image that doesn't appear: the file name must match exactly, including lower case.

**Tips for good screenshots**
- Crop out unrelated things (taskbar, other tabs, personal bookmarks).
- Make terminal text readable: increase the terminal font with **Ctrl + =** before capturing.
- For terminal figures, include the **command** and its **output** in the same screenshot.
