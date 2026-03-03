/**
 * retryWithBackoff
 *
 * Wraps a GitHub API call with:
 *   - Pre-call rate-limit monitoring (waits automatically if < 10 requests remain)
 *   - Exponential backoff retry on failure (up to maxRetries attempts)
 *
 * @param {Function} github  - The github object from actions/github-script
 * @param {Function} fn      - Async function that performs the API call
 * @param {number}   maxRetries    - Maximum number of attempts (default: 3)
 * @param {number}   initialDelay  - Initial delay in ms, doubles each retry (default: 2000)
 * @returns {Promise<*>} Result of fn()
 */
async function retryWithBackoff(
  github,
  fn,
  maxRetries = 3,
  initialDelay = 2000,
) {
  let lastError;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      // Check rate limit before making the API call
      const { data: rateLimit } = await github.rest.rateLimit.get();
      const remaining = rateLimit.rate.remaining;
      const resetTime = new Date(rateLimit.rate.reset * 1000);

      console.log(
        `Rate limit status: ${remaining} requests remaining, resets at ${resetTime}`,
      );

      // If rate limit is low, wait until it resets
      if (remaining < 10) {
        const waitTime = resetTime.getTime() - Date.now();
        if (waitTime > 0) {
          console.log(
            `Rate limit low. Waiting ${Math.ceil(waitTime / 1000)}s until reset...`,
          );
          await new Promise((resolve) => setTimeout(resolve, waitTime + 1000));
        }
      }

      // Execute the API call
      return await fn();
    } catch (error) {
      lastError = error;

      // Log whether this is a rate-limit error or a general failure
      const isRateLimit =
        error.status === 403 &&
        (error.message.includes("rate limit") ||
          error.message.includes("API rate limit"));

      console.error(
        `Attempt ${attempt}/${maxRetries} failed${isRateLimit ? " (rate limit)" : ""}:`,
        error.message,
      );

      if (attempt < maxRetries) {
        const delay = initialDelay * Math.pow(2, attempt - 1);
        console.log(`Retrying in ${delay}ms...`);
        await new Promise((resolve) => setTimeout(resolve, delay));
      } else {
        console.error("All retry attempts exhausted");
        throw error;
      }
    }
  }

  throw lastError;
}

module.exports = { retryWithBackoff };
