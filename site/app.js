(() => {
  const button = document.querySelector("[data-copy-command]");
  const command = document.querySelector("[data-command]");
  const status = document.querySelector("#copy-status");

  if (!button || !command || !status) {
    return;
  }

  const defaultLabel = button.textContent.trim();
  let resetTimer;

  const fallbackCopy = (value) => {
    const selection = document.getSelection();
    const selectedRange = selection && selection.rangeCount ? selection.getRangeAt(0) : null;
    const textArea = document.createElement("textarea");

    textArea.value = value;
    textArea.setAttribute("readonly", "");
    textArea.style.position = "fixed";
    textArea.style.opacity = "0";
    document.body.append(textArea);
    textArea.select();

    let copied = false;
    try {
      copied = document.execCommand("copy");
    } finally {
      textArea.remove();
      if (selection) {
        selection.removeAllRanges();
        if (selectedRange) {
          selection.addRange(selectedRange);
        }
      }
    }

    return copied;
  };

  const resetButton = () => {
    button.textContent = defaultLabel;
    button.removeAttribute("data-copied");
  };

  button.addEventListener("click", async () => {
    const value = command.textContent.trim();

    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(value);
      } else if (!fallbackCopy(value)) {
        throw new Error("Clipboard access is unavailable.");
      }

      window.clearTimeout(resetTimer);
      button.textContent = "Copied";
      button.dataset.copied = "true";
      status.textContent = "Command copied. Run it in your local terminal; this page did not execute it.";
      resetTimer = window.setTimeout(resetButton, 2200);
    } catch {
      status.textContent = "Could not copy automatically. Select the command above and copy it manually.";
    }
  });
})();
