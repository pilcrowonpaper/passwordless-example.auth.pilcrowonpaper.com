window.addEventListener("pageshow", () => {
	const buttonElements = document.getElementsByTagName("button");
	for (const buttonElement of buttonElements) {
		buttonElement.disabled = false;
	}
});
