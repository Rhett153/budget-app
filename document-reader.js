'use strict';

(function () {
  const PDFJS_VERSION = '4.10.38';
  const TESSERACT_VERSION = '6.0.0';
  let pdfModulePromise;
  let tesseractModulePromise;

  function loadPdfJs() {
    if (!pdfModulePromise) {
      pdfModulePromise = import('https://cdn.jsdelivr.net/npm/pdfjs-dist@' + PDFJS_VERSION + '/build/pdf.mjs').then(function (pdfjs) {
        pdfjs.GlobalWorkerOptions.workerSrc = 'https://cdn.jsdelivr.net/npm/pdfjs-dist@' + PDFJS_VERSION + '/build/pdf.worker.mjs';
        return pdfjs;
      });
    }
    return pdfModulePromise;
  }

  function loadTesseract() {
    if (!tesseractModulePromise) tesseractModulePromise = import('https://cdn.jsdelivr.net/npm/tesseract.js@' + TESSERACT_VERSION + '/+esm');
    return tesseractModulePromise;
  }

  async function recognize(image, progress) {
    const tesseract = await loadTesseract();
    const worker = await tesseract.createWorker('eng', 1, {
      logger: function (message) {
        if (progress && message.status === 'recognizing text') progress(message.progress || 0);
      }
    });
    try {
      const result = await worker.recognize(image);
      return result.data.text || '';
    } finally {
      await worker.terminate();
    }
  }

  function textLines(items) {
    const rows = new Map();
    items.forEach(function (item) {
      if (!item.str || !item.str.trim()) return;
      const y = Math.round(Number(item.transform && item.transform[5] || 0) / 3) * 3;
      if (!rows.has(y)) rows.set(y, []);
      rows.get(y).push(item);
    });
    return Array.from(rows.entries()).sort(function (a, b) { return b[0] - a[0]; }).map(function (entry) {
      return entry[1].sort(function (a, b) { return Number(a.transform && a.transform[4] || 0) - Number(b.transform && b.transform[4] || 0); }).map(function (item) { return item.str; }).join(' ').replace(/\s+/g, ' ').trim();
    }).filter(Boolean).join('\n');
  }

  async function renderPage(page) {
    const base = page.getViewport({ scale: 1 });
    const scale = Math.min(2, Math.max(1.35, 1800 / Math.max(base.width, base.height)));
    const viewport = page.getViewport({ scale: scale });
    const canvas = document.createElement('canvas');
    canvas.width = Math.ceil(viewport.width);
    canvas.height = Math.ceil(viewport.height);
    const context = canvas.getContext('2d', { willReadFrequently: true });
    await page.render({ canvas: canvas, canvasContext: context, viewport: viewport }).promise;
    return canvas;
  }

  async function extractPdf(file, progress) {
    const pdfjs = await loadPdfJs();
    const pdf = await pdfjs.getDocument({ data: new Uint8Array(await file.arrayBuffer()) }).promise;
    if (pdf.numPages > 20) throw new Error('This version can read up to 20 pages per PDF. Split the statement into smaller files.');
    const pages = [];
    let usedOcr = false;
    for (let pageNumber = 1; pageNumber <= pdf.numPages; pageNumber += 1) {
      if (progress) progress('Reading PDF page ' + pageNumber + ' of ' + pdf.numPages + '…');
      const page = await pdf.getPage(pageNumber);
      const content = await page.getTextContent();
      let text = textLines(content.items || []);
      if (text.replace(/\s/g, '').length < 35) {
        usedOcr = true;
        if (progress) progress('Recognizing text on page ' + pageNumber + ' of ' + pdf.numPages + '…');
        const canvas = await renderPage(page);
        text = await recognize(canvas, function (ratio) {
          if (progress) progress('Recognizing text on page ' + pageNumber + ' of ' + pdf.numPages + '… ' + Math.round(ratio * 100) + '%');
        });
        canvas.width = 1; canvas.height = 1;
      }
      pages.push(text);
    }
    return { text: pages.join('\n'), method: usedOcr ? 'PDF text and OCR' : 'PDF text extraction' };
  }

  async function extract(file, progress) {
    const type = String(file.type || '').toLowerCase();
    const extension = String(file.name || '').split('.').pop().toLowerCase();
    if (type === 'application/pdf' || extension === 'pdf') return extractPdf(file, progress);
    if (type === 'image/png' || type === 'image/jpeg' || ['png', 'jpg', 'jpeg'].includes(extension)) {
      if (progress) progress('Preparing on-device text recognition…');
      const text = await recognize(file, function (ratio) {
        if (progress) progress('Recognizing image text… ' + Math.round(ratio * 100) + '%');
      });
      return { text: text, method: 'Image OCR' };
    }
    throw new Error('Choose a CSV, PDF, PNG, or JPEG statement.');
  }

  window.BudgetDocumentReader = { extract: extract };
}());
