// utils/fieldConverter.js
const convertToSnakeCase = (obj) => {
  const converted = {};
  for (const [key, value] of Object.entries(obj)) {
    const snakeKey = key.replace(/([A-Z])/g, '_$1').toLowerCase();
    converted[snakeKey] = value;
  }
  return converted;
};

const convertToCamelCase = (obj) => {
  const converted = {};
  for (const [key, value] of Object.entries(obj)) {
    const camelKey = key.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());
    converted[camelKey] = value;
  }
  return converted;
};

module.exports = { convertToSnakeCase, convertToCamelCase };