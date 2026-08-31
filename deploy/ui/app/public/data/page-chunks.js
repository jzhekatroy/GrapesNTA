/* Lazy page chunks: manifest-driven loader with babel | bundled strategies. */

const PageChunks = (() => {
  const manifest = window.PAGE_CHUNKS_MANIFEST;
  if (!manifest?.chunks) {
    throw new Error('PAGE_CHUNKS_MANIFEST не загружен');
  }

  const loadedScripts = new Set();
  const loadedChunks = new Set();
  const inflightChunks = new Map();

  function resolveMode() {
    const explicit = window.__GRAPES_RUNTIME__?.frontendMode;
    if (explicit === 'babel' || explicit === 'bundled') return explicit;
    if (window.__GRAPES_BUNDLE_MANIFEST__) return 'bundled';
    return 'babel';
  }

  function resolveChunkId(pageId) {
    const id = String(pageId || '').trim();
    if (!id) return 'coming-soon';
    return manifest.aliases[id] || id;
  }

  function chunkSpec(chunkId) {
    return manifest.chunks[chunkId] || null;
  }

  function bootLabel(src) {
    return src.split('/').pop() || src;
  }

  function logStep(label) {
    if (window.BootLog?.step) {
      BootLog.step(label);
    }
  }

  function wrapTransformedModule(code, src) {
    const url = String(src || '').replace(/\\/g, '/');
    return `(function(){\n${code}\n})();\n//# sourceURL=${url}`;
  }

  function appendScript(text) {
    const script = document.createElement('script');
    script.text = text;
    document.body.appendChild(script);
    return Promise.resolve();
  }

  function loadScriptSrc(src) {
    if (loadedScripts.has(src)) return Promise.resolve();
    loadedScripts.add(src);

    return new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = src;
      script.onload = () => {
        logStep(`загружен · script · ${bootLabel(src)}`);
        resolve();
      };
      script.onerror = () => {
        loadedScripts.delete(src);
        reject(new Error(`Не удалось загрузить ${src}`));
      };
      document.body.appendChild(script);
    });
  }

  async function loadJsxScript(src) {
    if (loadedScripts.has(src)) return;
    loadedScripts.add(src);

    if (!window.Babel?.transform) {
      throw new Error('Babel не загружен (frontendMode=babel)');
    }

    const label = bootLabel(src);
    logStep(`chunk · fetch · ${label}`);
    const res = await fetch(src, { cache: 'no-store' });
    if (!res.ok) {
      loadedScripts.delete(src);
      throw new Error(`HTTP ${res.status} · ${src}`);
    }
    const code = await res.text();
    logStep(`chunk · transform · ${label}`);
    let transformed;
    try {
      transformed = Babel.transform(code, { presets: ['react'] }).code;
    } catch (err) {
      loadedScripts.delete(src);
      throw err;
    }
    logStep(`chunk · exec · ${label}`);
    try {
      await appendScript(wrapTransformedModule(transformed, src));
    } catch (err) {
      loadedScripts.delete(src);
      throw err;
    }
    logStep(`chunk · готов · ${label}`);
  }

  async function loadScript(src) {
    if (loadedScripts.has(src)) return;
    if (/\.jsx(?:\?|#|$)/i.test(src)) {
      await loadJsxScript(src);
      return;
    }
    await loadScriptSrc(src);
  }

  async function babelLoadChunk(chunkId) {
    const spec = chunkSpec(chunkId);
    if (!spec) {
      throw new Error(`Неизвестный чанк: ${chunkId}`);
    }
    for (const src of spec.scripts) {
      await loadScript(src);
    }
  }

  async function bundledLoadChunk(chunkId) {
    const bundleManifest = window.__GRAPES_BUNDLE_MANIFEST__;
    if (!bundleManifest) {
      throw new Error('__GRAPES_BUNDLE_MANIFEST__ не найден (frontendMode=bundled)');
    }
    const src = bundleManifest.chunks?.[chunkId] || bundleManifest[chunkId];
    if (!src) {
      throw new Error(`Бандл не найден для чанка: ${chunkId}`);
    }
    if (loadedScripts.has(src)) return;
    logStep(`chunk · bundle · ${chunkId}`);
    await loadScriptSrc(src);
  }

  const strategies = {
    babel: babelLoadChunk,
    bundled: bundledLoadChunk,
  };

  async function loadChunk(chunkId) {
    const id = resolveChunkId(chunkId);
    if (loadedChunks.has(id)) return;
    if (inflightChunks.has(id)) return inflightChunks.get(id);

    const spec = chunkSpec(id);
    if (!spec) {
      return;
    }

    const mode = resolveMode();
    const strategy = strategies[mode];
    if (!strategy) {
      throw new Error(`Неизвестный frontendMode: ${mode}`);
    }

    const promise = strategy(id)
      .then(() => {
        loadedChunks.add(id);
      })
      .finally(() => {
        inflightChunks.delete(id);
      });

    inflightChunks.set(id, promise);
    return promise;
  }

  function isLoaded(pageId) {
    const id = resolveChunkId(pageId);
    const spec = chunkSpec(id);
    if (!spec) return true;
    return loadedChunks.has(id);
  }

  function preload(pageId) {
    load(pageId).catch(() => {});
  }

  function load(pageId) {
    return loadChunk(resolveChunkId(pageId));
  }

  function exportNameFor(pageId, exportName) {
    if (exportName) return exportName;
    const id = resolveChunkId(pageId);
    const spec = chunkSpec(id);
    return spec?.exports?.default || null;
  }

  function component(pageId, exportName) {
    const id = resolveChunkId(pageId);
    const name = exportNameFor(pageId, exportName);
    if (!name) return null;

    const fromRegistry = window.__GRAPES_CHUNKS__?.[id]?.[name];
    if (fromRegistry) return fromRegistry;

    return window[name] || null;
  }

  return {
    resolveChunkId,
    load,
    preload,
    isLoaded,
    component,
    resolveMode,
  };
})();

Object.assign(window, { PageChunks });
