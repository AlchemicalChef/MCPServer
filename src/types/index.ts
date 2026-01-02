import { z } from 'zod';

// Common response types
export interface ToolResponse {
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
}

export interface ResourceContents {
  contents: Array<{
    uri: string;
    mimeType?: string;
    text?: string;
    blob?: string;
  }>;
}

export interface PromptMessages {
  messages: Array<{
    role: 'user' | 'assistant';
    content: {
      type: 'text';
      text: string;
    };
  }>;
}

// Re-export zod for convenience
export { z };
