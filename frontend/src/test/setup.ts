import '@testing-library/jest-dom';

// Polyfill window.scrollTo
Object.defineProperty(window, 'scrollTo', {
  value: () => {},
  writable: true,
});

// Polyfill clipboard
Object.defineProperty(navigator, 'clipboard', {
  value: {
    writeText: async () => {},
  },
  writable: true,
});

// Polyfill URL.createObjectURL and URL.revokeObjectURL
if (typeof window.URL.createObjectURL === 'undefined') {
  Object.defineProperty(window.URL, 'createObjectURL', {
    value: () => 'blob:mock-url',
    writable: true,
  });
}
if (typeof window.URL.revokeObjectURL === 'undefined') {
  Object.defineProperty(window.URL, 'revokeObjectURL', {
    value: () => {},
    writable: true,
  });
}
