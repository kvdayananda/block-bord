// Options JS for Block Bord AI
document.addEventListener('DOMContentLoaded', () => {
    const apiUrlInput = document.getElementById('api-url');
    const apiKeyInput = document.getElementById('api-key');
    const saveBtn = document.getElementById('save');
    const status = document.getElementById('status');

    // Load current values
    chrome.storage.local.get(['apiUrl', 'apiKey'], (result) => {
        if (result.apiUrl) apiUrlInput.value = result.apiUrl;
        if (result.apiKey) apiKeyInput.value = result.apiKey;
    });

    saveBtn.addEventListener('click', () => {
        const apiUrl = apiUrlInput.value.trim();
        const apiKey = apiKeyInput.value.trim();

        chrome.storage.local.set({ 
            apiUrl: apiUrl, 
            apiKey: apiKey 
        }, () => {
            status.textContent = 'Settings saved successfully!';
            status.className = 'success';
            setTimeout(() => { status.textContent = ''; }, 3000);
        });
    });
});
