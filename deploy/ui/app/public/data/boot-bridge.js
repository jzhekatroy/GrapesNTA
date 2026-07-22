/* Хуки после React/Babel — дополнительные шаги boot-лога */

(function bootBridge() {
  if (!window.BootLog) return;

  function hookReactDom() {
    if (!window.ReactDOM?.createRoot) return false;

    const origCreateRoot = ReactDOM.createRoot.bind(ReactDOM);
    ReactDOM.createRoot = function createRoot(container, options) {
      BootLog.step('ReactDOM.createRoot');
      const root = origCreateRoot(container, options);
      const origRender = root.render.bind(root);
      root.render = function render(element) {
        BootLog.step('root.render · старт');
        const result = origRender(element);
        requestAnimationFrame(() => BootLog.step('root.render · кадр отрисован'));
        return result;
      };
      return root;
    };
    return true;
  }

  function hookBabel() {
    if (!window.Babel?.transformScriptTags) return false;
    if (Babel.__bootHooked) return true;
    Babel.__bootHooked = true;

    BootLog.step('Babel готов');
    const orig = Babel.transformScriptTags.bind(Babel);
    Babel.transformScriptTags = function transformScriptTags(...args) {
      BootLog.step('Babel · трансформация JSX');
      return orig(...args);
    };
    return true;
  }

  function init() {
    if (!hookReactDom()) BootLog.step('ReactDOM ещё не готов');
    if (!hookBabel()) BootLog.fail('Babel не найден после загрузки babel.min.js');
  }

  init();
})();
