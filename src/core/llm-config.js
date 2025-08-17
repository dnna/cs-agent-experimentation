/**
 * LLM Configuration Manager
 * Handles configuration for different LLM providers
 */
export class LLMConfig {
  constructor() {
    this.providers = {
      openai: {
        name: 'OpenAI',
        models: {
          'gpt-4.1': {
            contextWindow: 1047576,
            maxTokens: 32768,
            cost: { input: 0.002, output: 0.008 },
            recommended: false
          },
          'gpt-4.1-mini': {
            contextWindow: 1047576,
            maxTokens: 32768,
            cost: { input: 0.0004, output: 0.0016 },
            recommended: false
          },
          'gpt-4.1-nano': {
            contextWindow: 1047576,
            maxTokens: 32768,
            cost: { input: 0.0001, output: 0.0004 },
            recommended: false
          },
          'gpt-5-mini': {
            contextWindow: 400000,
            maxTokens: 128000,
            cost: { input: 0.00025, output: 0.002 },
            recommended: true,
            features: ['reasoning_effort', 'verbosity']
          }
        },
        apiKeyEnv: 'OPENAI_API_KEY',
        defaultModel: 'gpt-5-mini'
      },
      anthropic: {
        name: 'Anthropic',
        models: {
          'claude-3-sonnet-20240229': {
            contextWindow: 200000,
            maxTokens: 4000,
            cost: { input: 0.003, output: 0.015 },
            recommended: true
          },
          'claude-3-opus-20240229': {
            contextWindow: 200000,
            maxTokens: 4000,
            cost: { input: 0.015, output: 0.075 },
            recommended: false
          },
          'claude-3-haiku-20240307': {
            contextWindow: 200000,
            maxTokens: 4000,
            cost: { input: 0.00025, output: 0.00125 },
            recommended: false
          }
        },
        apiKeyEnv: 'ANTHROPIC_API_KEY',
        defaultModel: 'claude-3-sonnet-20240229'
      },
      google: {
        name: 'Google',
        models: {
          'gemini-2.5-pro': {
            contextWindow: 1000000,
            maxTokens: 8192,
            cost: { input: 0.00125, output: 0.01 },
            recommended: false
          },
          'gemini-2.5-flash': {
            contextWindow: 1000000,
            maxTokens: 8192,
            cost: { input: 0.00015, output: 0.0006 },
            recommended: true
          }
        },
        apiKeyEnv: 'GOOGLE_API_KEY',
        defaultModel: 'gemini-2.5-flash'
      }
    };
  }

  /**
   * Get configuration for a provider
   */
  getProviderConfig(provider) {
    return this.providers[provider] || null;
  }

  /**
   * Get all available providers
   */
  getAvailableProviders() {
    return Object.keys(this.providers);
  }

  /**
   * Get models for a provider
   */
  getProviderModels(provider) {
    const config = this.getProviderConfig(provider);
    return config ? Object.keys(config.models) : [];
  }

  /**
   * Get model configuration
   */
  getModelConfig(provider, model) {
    const config = this.getProviderConfig(provider);
    return config?.models?.[model] || null;
  }

  /**
   * Get default model for provider
   */
  getDefaultModel(provider) {
    const config = this.getProviderConfig(provider);
    return config?.defaultModel || null;
  }

  /**
   * Get recommended models across all providers
   */
  getRecommendedModels() {
    const recommended = {};
    
    for (const [provider, config] of Object.entries(this.providers)) {
      for (const [model, modelConfig] of Object.entries(config.models)) {
        if (modelConfig.recommended) {
          recommended[provider] = recommended[provider] || [];
          recommended[provider].push(model);
        }
      }
    }
    
    return recommended;
  }

  /**
   * Check if API key is available for provider
   */
  hasApiKey(provider) {
    const config = this.getProviderConfig(provider);
    if (!config) return false;
    
    return !!process.env[config.apiKeyEnv];
  }

  /**
   * Get available providers with API keys
   */
  getAvailableProvidersWithKeys() {
    return this.getAvailableProviders().filter(provider => this.hasApiKey(provider));
  }

  /**
   * Get optimal configuration for security analysis
   */
  getSecurityAnalysisConfig() {
    const configs = [
      {
        provider: 'openai',
        model: 'gpt-5-mini',
        temperature: 0.1,
        maxTokens: 2000,
        reason: 'Latest model with enhanced reasoning for security analysis with 400K context window'
      },
      {
        provider: 'anthropic',
        model: 'claude-3-sonnet-20240229',
        temperature: 0.1,
        maxTokens: 2000,
        reason: 'Excellent for detailed security analysis with large context'
      },
      {
        provider: 'google',
        model: 'gemini-2.5-flash',
        temperature: 0.1,
        maxTokens: 2000,
        reason: 'Cost-effective option for security analysis with thinking capabilities'
      }
    ];

    // Return first available configuration
    for (const config of configs) {
      if (this.hasApiKey(config.provider)) {
        return config;
      }
    }

    return null;
  }

  /**
   * Validate configuration
   */
  validateConfig(config) {
    const errors = [];
    
    if (!config.provider) {
      errors.push('Provider is required');
    } else if (!this.providers[config.provider]) {
      errors.push(`Invalid provider: ${config.provider}`);
    }
    
    if (!config.model) {
      errors.push('Model is required');
    } else if (config.provider && !this.providers[config.provider]?.models?.[config.model]) {
      errors.push(`Invalid model: ${config.model} for provider: ${config.provider}`);
    }
    
    if (config.temperature && (config.temperature < 0 || config.temperature > 1)) {
      errors.push('Temperature must be between 0 and 1');
    }
    
    if (config.maxTokens && config.maxTokens < 1) {
      errors.push('Max tokens must be positive');
    }
    
    return {
      isValid: errors.length === 0,
      errors
    };
  }

  /**
   * Get cost estimate for analysis
   */
  estimateCost(provider, model, inputTokens, outputTokens) {
    const modelConfig = this.getModelConfig(provider, model);
    if (!modelConfig) return null;
    
    const inputCost = (inputTokens / 1000) * modelConfig.cost.input;
    const outputCost = (outputTokens / 1000) * modelConfig.cost.output;
    
    return {
      inputCost,
      outputCost,
      totalCost: inputCost + outputCost,
      currency: 'USD'
    };
  }

  /**
   * Get configuration summary
   */
  getConfigSummary() {
    const availableProviders = this.getAvailableProvidersWithKeys();
    const recommended = this.getRecommendedModels();
    const optimal = this.getSecurityAnalysisConfig();
    
    return {
      availableProviders,
      recommendedModels: recommended,
      optimalConfig: optimal,
      totalProviders: this.getAvailableProviders().length,
      providersWithKeys: availableProviders.length
    };
  }
}

// Singleton instance
export const llmConfig = new LLMConfig();
export default LLMConfig;