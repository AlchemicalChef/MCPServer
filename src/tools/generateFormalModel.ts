import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { logToolInvocation, logOutput } from '../utils/auditLog.js';
import { sanitize, validateInput } from '../utils/sanitize.js';

type SupportedLanguage = 'javascript' | 'typescript' | 'python' | 'go' | 'php' | 'ruby';
type ModelType = 'state-machine' | 'tlaplus' | 'alloy' | 'contracts' | 'petri-net';

interface StateVariable {
  name: string;
  type: string;
  initialValue?: string;
  line: number;
}

interface State {
  name: string;
  type: 'initial' | 'normal' | 'final' | 'error';
  line?: number;
}

interface Transition {
  from: string;
  to: string;
  action: string;
  guard?: string;
  line?: number;
}

interface FunctionSignature {
  name: string;
  params: Array<{ name: string; type: string }>;
  returnType: string;
  preconditions: string[];
  postconditions: string[];
  modifies: string[];
  line: number;
}

interface Invariant {
  expression: string;
  scope: string;
  line: number;
}

interface Place {
  name: string;
  tokens: number;
}

interface PetriTransition {
  name: string;
  inputs: string[];
  outputs: string[];
  guard?: string;
}

interface FormalModel {
  type: ModelType;
  language: SupportedLanguage;
  states?: State[];
  transitions?: Transition[];
  variables?: StateVariable[];
  functions?: FunctionSignature[];
  invariants?: Invariant[];
  places?: Place[];
  petriTransitions?: PetriTransition[];
  specification: string;
}

// Language-specific patterns for extraction
const PATTERNS: Record<SupportedLanguage, {
  stateEnum: RegExp;
  stateAssignment: RegExp;
  functionDef: RegExp;
  variableDecl: RegExp;
  conditionalTransition: RegExp;
  switchCase: RegExp;
  assertion: RegExp;
  returnStatement: RegExp;
  throwStatement: RegExp;
  asyncOperation: RegExp;
  lockAcquire: RegExp;
  lockRelease: RegExp;
}> = {
  javascript: {
    stateEnum: /(?:const|let|var)\s+(\w+)\s*=\s*\{([^}]+)\}/g,
    stateAssignment: /(?:this\.)?(?:state|status|phase|mode)\s*=\s*['"`]?(\w+)['"`]?/g,
    functionDef: /(?:async\s+)?(?:function\s+(\w+)|(\w+)\s*[=:]\s*(?:async\s+)?(?:function|\([^)]*\)\s*=>))/g,
    variableDecl: /(?:const|let|var)\s+(\w+)(?:\s*:\s*(\w+))?\s*=\s*([^;]+)/g,
    conditionalTransition: /if\s*\(([^)]+)\)\s*\{[^}]*(?:state|status)\s*=\s*['"`]?(\w+)['"`]?/g,
    switchCase: /case\s+['"`]?(\w+)['"`]?\s*:/g,
    assertion: /(?:assert|expect|should|must)\s*\(([^)]+)\)/g,
    returnStatement: /return\s+([^;]+)/g,
    throwStatement: /throw\s+(?:new\s+)?(\w+)/g,
    asyncOperation: /await\s+(\w+(?:\.\w+)*)\s*\(/g,
    lockAcquire: /(?:acquire|lock|mutex\.lock|semaphore\.wait)\s*\(/g,
    lockRelease: /(?:release|unlock|mutex\.unlock|semaphore\.signal)\s*\(/g,
  },
  typescript: {
    stateEnum: /(?:enum\s+(\w+)\s*\{([^}]+)\}|type\s+(\w+)\s*=\s*([^;]+))/g,
    stateAssignment: /(?:this\.)?(?:state|status|phase|mode)\s*=\s*(?:['"`](\w+)['"`]|(\w+)\.(\w+))/g,
    functionDef: /(?:async\s+)?(?:(?:public|private|protected)\s+)?(?:static\s+)?(\w+)\s*(?:<[^>]+>)?\s*\([^)]*\)(?:\s*:\s*(\w+(?:<[^>]+>)?))?/g,
    variableDecl: /(?:const|let|var|private|public|protected)\s+(\w+)\s*(?::\s*([^=]+))?\s*=\s*([^;]+)/g,
    conditionalTransition: /if\s*\(([^)]+)\)\s*\{[^}]*(?:state|status)\s*=\s*(?:['"`]?(\w+)['"`]?|(\w+)\.(\w+))/g,
    switchCase: /case\s+(?:['"`](\w+)['"`]|(\w+)\.(\w+))\s*:/g,
    assertion: /(?:assert|expect|should|must)\s*[<(]([^)>]+)[)>]/g,
    returnStatement: /return\s+([^;]+)/g,
    throwStatement: /throw\s+(?:new\s+)?(\w+)/g,
    asyncOperation: /await\s+(\w+(?:\.\w+)*)\s*[<(]/g,
    lockAcquire: /(?:acquire|lock|mutex\.lock|semaphore\.wait)\s*\(/g,
    lockRelease: /(?:release|unlock|mutex\.unlock|semaphore\.signal)\s*\(/g,
  },
  python: {
    stateEnum: /class\s+(\w+)\s*\(\s*Enum\s*\)\s*:\s*((?:\n\s+\w+\s*=\s*[^\n]+)+)/g,
    stateAssignment: /(?:self\.)?(?:state|status|phase|mode)\s*=\s*(?:['"](\w+)['"]|(\w+)\.(\w+))/g,
    functionDef: /(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)(?:\s*->\s*(\w+))?/g,
    variableDecl: /(\w+)\s*(?::\s*(\w+))?\s*=\s*([^\n]+)/g,
    conditionalTransition: /if\s+([^:]+):\s*\n\s*(?:self\.)?(?:state|status)\s*=\s*(?:['"](\w+)['"]|(\w+)\.(\w+))/g,
    switchCase: /case\s+(?:['"](\w+)['"]|(\w+)\.(\w+))\s*:/g,
    assertion: /assert\s+([^,\n]+)/g,
    returnStatement: /return\s+([^\n]+)/g,
    throwStatement: /raise\s+(\w+)/g,
    asyncOperation: /await\s+(\w+(?:\.\w+)*)\s*\(/g,
    lockAcquire: /(?:acquire|lock|async\s+with\s+\w+\.lock)\s*\(/g,
    lockRelease: /(?:release|unlock)\s*\(/g,
  },
  go: {
    stateEnum: /const\s*\(\s*((?:\s*\w+(?:\s+\w+)?\s*=\s*(?:iota|[^\n]+)\s*)+)\)/g,
    stateAssignment: /(?:\w+\.)?(?:state|status|phase|mode)\s*=\s*(\w+)/g,
    functionDef: /func\s+(?:\(\s*\w+\s+\*?(\w+)\s*\)\s+)?(\w+)\s*\(([^)]*)\)(?:\s*(?:\(([^)]*)\)|(\w+)))?/g,
    variableDecl: /(?:var\s+(\w+)\s+(\w+)|(\w+)\s*:=\s*([^\n]+))/g,
    conditionalTransition: /if\s+([^{]+)\s*\{[^}]*(?:state|status)\s*=\s*(\w+)/g,
    switchCase: /case\s+(\w+)\s*:/g,
    assertion: /(?:assert|require)\s*\(([^)]+)\)/g,
    returnStatement: /return\s+([^\n]+)/g,
    throwStatement: /panic\s*\(([^)]+)\)/g,
    asyncOperation: /go\s+(\w+)\s*\(/g,
    lockAcquire: /(?:\.Lock|\.RLock|<-\s*\w+)\s*\(/g,
    lockRelease: /(?:\.Unlock|\.RUnlock|\w+\s*<-)\s*\(/g,
  },
  php: {
    stateEnum: /(?:const|define)\s*\(?\s*['"]?(\w+)['"]?\s*(?:,|=)\s*([^;)]+)/g,
    stateAssignment: /\$(?:this->)?(?:state|status|phase|mode)\s*=\s*(?:['"](\w+)['"]|self::(\w+)|(\w+)::(\w+))/g,
    functionDef: /(?:public|private|protected)?\s*(?:static)?\s*function\s+(\w+)\s*\(([^)]*)\)(?:\s*:\s*(\w+))?/g,
    variableDecl: /\$(\w+)\s*=\s*([^;]+)/g,
    conditionalTransition: /if\s*\(([^)]+)\)\s*\{[^}]*\$(?:this->)?(?:state|status)\s*=\s*(?:['"](\w+)['"]|(\w+)::(\w+))/g,
    switchCase: /case\s+(?:['"](\w+)['"]|(\w+)::(\w+))\s*:/g,
    assertion: /assert\s*\(([^)]+)\)/g,
    returnStatement: /return\s+([^;]+)/g,
    throwStatement: /throw\s+new\s+(\w+)/g,
    asyncOperation: /(?:async|await)\s*\(?\s*(\w+)/g,
    lockAcquire: /(?:flock|sem_acquire|mutex->lock)\s*\(/g,
    lockRelease: /(?:flock|sem_release|mutex->unlock)\s*\(/g,
  },
  ruby: {
    stateEnum: /module\s+(\w+)\s+((?:\s*\w+\s*=\s*[^\n]+)+)/g,
    stateAssignment: /@(?:state|status|phase|mode)\s*=\s*(?::(\w+)|['"](\w+)['"])/g,
    functionDef: /def\s+(?:self\.)?(\w+)(?:\(([^)]*)\))?/g,
    variableDecl: /@(\w+)\s*=\s*([^\n]+)/g,
    conditionalTransition: /if\s+([^\n]+)\n\s*@(?:state|status)\s*=\s*(?::(\w+)|['"](\w+)['"])/g,
    switchCase: /when\s+(?::(\w+)|['"](\w+)['"])/g,
    assertion: /(?:assert|expect|should)\s*[({]([^)}]+)[)}]/g,
    returnStatement: /(?:return\s+|^(?!\s*(?:if|unless|while|until|for|def|class|module|begin|case|do)\s))\s*([^\n]+)$/gm,
    throwStatement: /raise\s+(\w+)/g,
    asyncOperation: /(?:async|Thread\.new|Fiber\.new)\s*[{(]/g,
    lockAcquire: /(?:synchronize|lock|acquire)\s*[{(]/g,
    lockRelease: /(?:unlock|release)\s*[{(]/g,
  },
};

// Extract states from code
function extractStates(code: string, language: SupportedLanguage): State[] {
  const states: State[] = [];
  const lines = code.split('\n');
  const patterns = PATTERNS[language];

  // Look for enum-style state definitions
  let match;
  const enumPattern = new RegExp(patterns.stateEnum.source, patterns.stateEnum.flags);
  while ((match = enumPattern.exec(code)) !== null) {
    const enumBody = match[2] || match[4] || '';
    const stateNames = enumBody.match(/\w+/g) || [];
    stateNames.forEach((name, index) => {
      if (name && !['const', 'let', 'var', 'iota', 'auto'].includes(name.toLowerCase())) {
        states.push({
          name,
          type: index === 0 ? 'initial' : 'normal',
        });
      }
    });
  }

  // Look for state assignments to find more states
  const assignPattern = new RegExp(patterns.stateAssignment.source, patterns.stateAssignment.flags);
  lines.forEach((line, lineNum) => {
    while ((match = assignPattern.exec(line)) !== null) {
      const stateName = match[1] || match[2] || match[3];
      if (stateName && !states.find(s => s.name === stateName)) {
        const isError = /error|fail|invalid|reject/i.test(stateName);
        const isFinal = /done|complete|finish|success|end/i.test(stateName);
        states.push({
          name: stateName,
          type: isError ? 'error' : isFinal ? 'final' : 'normal',
          line: lineNum + 1,
        });
      }
    }
  });

  // Look for switch cases as states
  const switchPattern = new RegExp(patterns.switchCase.source, patterns.switchCase.flags);
  while ((match = switchPattern.exec(code)) !== null) {
    const stateName = match[1] || match[2] || match[3];
    if (stateName && !states.find(s => s.name === stateName)) {
      states.push({
        name: stateName,
        type: 'normal',
      });
    }
  }

  return states;
}

// Extract transitions between states
function extractTransitions(code: string, language: SupportedLanguage, states: State[]): Transition[] {
  const transitions: Transition[] = [];
  const lines = code.split('\n');
  const patterns = PATTERNS[language];

  let currentState: string | null = null;

  lines.forEach((line, lineNum) => {
    // Track current state context
    const assignMatch = new RegExp(patterns.stateAssignment.source, 'g').exec(line);
    if (assignMatch) {
      const newState = assignMatch[1] || assignMatch[2] || assignMatch[3];
      if (currentState && newState && currentState !== newState) {
        // Extract guard condition if present
        let guard: string | undefined;
        const condMatch = new RegExp(patterns.conditionalTransition.source, 'g').exec(
          lines.slice(Math.max(0, lineNum - 3), lineNum + 1).join('\n')
        );
        if (condMatch) {
          guard = condMatch[1]?.trim();
        }

        transitions.push({
          from: currentState,
          to: newState,
          action: `transition_${transitions.length + 1}`,
          guard,
          line: lineNum + 1,
        });
      }
      currentState = newState;
    }
  });

  // Also look for explicit conditional transitions
  const condPattern = new RegExp(patterns.conditionalTransition.source, patterns.conditionalTransition.flags);
  let match;
  while ((match = condPattern.exec(code)) !== null) {
    const guard = match[1]?.trim();
    const toState = match[2] || match[3] || match[4];
    if (toState) {
      // Find the from state from context
      const linesBefore = code.substring(0, match.index).split('\n');
      let fromState = 'UNKNOWN';
      for (let i = linesBefore.length - 1; i >= 0 && i >= linesBefore.length - 20; i--) {
        const prevMatch = new RegExp(patterns.stateAssignment.source, 'g').exec(linesBefore[i]);
        if (prevMatch) {
          fromState = prevMatch[1] || prevMatch[2] || prevMatch[3] || 'UNKNOWN';
          break;
        }
      }

      if (!transitions.find(t => t.from === fromState && t.to === toState && t.guard === guard)) {
        transitions.push({
          from: fromState,
          to: toState,
          action: `guarded_transition`,
          guard,
        });
      }
    }
  }

  return transitions;
}

// Extract variables/state
function extractVariables(code: string, language: SupportedLanguage): StateVariable[] {
  const variables: StateVariable[] = [];
  const lines = code.split('\n');
  const patterns = PATTERNS[language];

  lines.forEach((line, lineNum) => {
    const varPattern = new RegExp(patterns.variableDecl.source, 'g');
    let match;
    while ((match = varPattern.exec(line)) !== null) {
      const name = match[1] || match[3];
      const type = match[2] || match[4] || 'unknown';
      const value = match[3] || match[4];

      if (name && !name.startsWith('_')) {
        variables.push({
          name,
          type: type?.trim() || 'unknown',
          initialValue: value?.trim(),
          line: lineNum + 1,
        });
      }
    }
  });

  return variables;
}

// Extract function signatures with pre/post conditions
function extractFunctions(code: string, language: SupportedLanguage): FunctionSignature[] {
  const functions: FunctionSignature[] = [];
  const lines = code.split('\n');
  const patterns = PATTERNS[language];

  const funcPattern = new RegExp(patterns.functionDef.source, patterns.functionDef.flags);
  let match;

  while ((match = funcPattern.exec(code)) !== null) {
    const lineNum = code.substring(0, match.index).split('\n').length;
    const name = match[1] || match[2];
    const paramsStr = match[3] || match[2] || '';
    const returnType = match[4] || match[5] || 'void';

    if (!name || ['if', 'for', 'while', 'switch', 'catch'].includes(name)) continue;

    // Parse parameters
    const params: Array<{ name: string; type: string }> = [];
    const paramMatches = paramsStr.matchAll(/(\w+)(?:\s*:\s*(\w+))?/g);
    for (const pm of paramMatches) {
      if (pm[1] && !['self', 'this', 'cls'].includes(pm[1])) {
        params.push({ name: pm[1], type: pm[2] || 'any' });
      }
    }

    // Extract function body to find assertions/conditions
    const funcStart = match.index;
    let braceCount = 0;
    let funcEnd = funcStart;
    let inFunc = false;

    for (let i = funcStart; i < code.length; i++) {
      if (code[i] === '{' || (language === 'python' && code[i] === ':' && !inFunc)) {
        braceCount++;
        inFunc = true;
      } else if (code[i] === '}' || (language === 'python' && braceCount > 0 && /^\S/.test(code.substring(i, i + 1)) && code[i] !== ' ')) {
        braceCount--;
        if (braceCount === 0) {
          funcEnd = i;
          break;
        }
      }
    }

    // Simple heuristic for Python: find next function or class definition
    if (language === 'python' || language === 'ruby') {
      const nextFuncMatch = code.substring(funcStart + match[0].length).search(/\n(?:def|class|async def)\s/);
      funcEnd = nextFuncMatch === -1 ? code.length : funcStart + match[0].length + nextFuncMatch;
    }

    const funcBody = code.substring(funcStart, funcEnd);

    // Extract preconditions from assertions at function start
    const preconditions: string[] = [];
    const postconditions: string[] = [];
    const modifies: string[] = [];

    const assertPattern = new RegExp(patterns.assertion.source, 'g');
    const bodyLines = funcBody.split('\n');
    let foundNonAssert = false;

    bodyLines.forEach((line, idx) => {
      const assertMatch = assertPattern.exec(line);
      if (assertMatch) {
        if (!foundNonAssert && idx < 5) {
          preconditions.push(assertMatch[1].trim());
        } else {
          postconditions.push(assertMatch[1].trim());
        }
      } else if (line.trim() && !line.trim().startsWith('//') && !line.trim().startsWith('#')) {
        foundNonAssert = true;
      }

      // Track modified variables
      const varMatch = /(?:this\.|self\.|@)(\w+)\s*=/.exec(line);
      if (varMatch && !modifies.includes(varMatch[1])) {
        modifies.push(varMatch[1]);
      }
    });

    functions.push({
      name,
      params,
      returnType: returnType?.trim() || 'void',
      preconditions,
      postconditions,
      modifies,
      line: lineNum,
    });
  }

  return functions;
}

// Extract invariants from code
function extractInvariants(code: string, language: SupportedLanguage): Invariant[] {
  const invariants: Invariant[] = [];
  const lines = code.split('\n');
  const patterns = PATTERNS[language];

  // Look for assertions that appear to be invariants (in loops or class-level)
  lines.forEach((line, lineNum) => {
    const assertPattern = new RegExp(patterns.assertion.source, 'g');
    let match;
    while ((match = assertPattern.exec(line)) !== null) {
      // Check context to determine scope
      let scope = 'function';
      const contextBefore = lines.slice(Math.max(0, lineNum - 10), lineNum).join('\n');

      if (/while|for|loop/.test(contextBefore)) {
        scope = 'loop';
      } else if (/class|struct|type/.test(contextBefore)) {
        scope = 'class';
      }

      invariants.push({
        expression: match[1].trim(),
        scope,
        line: lineNum + 1,
      });
    }
  });

  return invariants;
}

// Extract Petri net places and transitions (for concurrency)
function extractPetriNet(code: string, language: SupportedLanguage): { places: Place[]; transitions: PetriTransition[] } {
  const places: Place[] = [];
  const transitions: PetriTransition[] = [];
  const patterns = PATTERNS[language];

  // Find async operations and locks as places
  const asyncPattern = new RegExp(patterns.asyncOperation.source, 'g');
  const lockAcquirePattern = new RegExp(patterns.lockAcquire.source, 'g');
  const lockReleasePattern = new RegExp(patterns.lockRelease.source, 'g');

  let match;

  // Create places for resources/locks
  const resourcePlaces = new Set<string>();
  while ((match = lockAcquirePattern.exec(code)) !== null) {
    const context = code.substring(Math.max(0, match.index - 50), match.index);
    const resourceMatch = /(\w+)\.(?:lock|Lock|acquire)/.exec(context);
    if (resourceMatch) {
      resourcePlaces.add(resourceMatch[1]);
    }
  }

  resourcePlaces.forEach(resource => {
    places.push({ name: `${resource}_available`, tokens: 1 });
    places.push({ name: `${resource}_held`, tokens: 0 });

    transitions.push({
      name: `acquire_${resource}`,
      inputs: [`${resource}_available`],
      outputs: [`${resource}_held`],
    });

    transitions.push({
      name: `release_${resource}`,
      inputs: [`${resource}_held`],
      outputs: [`${resource}_available`],
    });
  });

  // Find async operations as transitions
  while ((match = asyncPattern.exec(code)) !== null) {
    const opName = match[1];
    if (!transitions.find(t => t.name === `async_${opName}`)) {
      places.push({ name: `${opName}_pending`, tokens: 0 });
      places.push({ name: `${opName}_complete`, tokens: 0 });

      transitions.push({
        name: `start_${opName}`,
        inputs: [],
        outputs: [`${opName}_pending`],
      });

      transitions.push({
        name: `complete_${opName}`,
        inputs: [`${opName}_pending`],
        outputs: [`${opName}_complete`],
      });
    }
  }

  return { places, transitions };
}

// Generate TLA+ specification
function generateTLAPlus(model: FormalModel): string {
  const lines: string[] = [];

  lines.push(`---- MODULE ${model.language.charAt(0).toUpperCase() + model.language.slice(1)}Model ----`);
  lines.push('EXTENDS Integers, Sequences, TLC');
  lines.push('');

  // Variables
  if (model.variables && model.variables.length > 0) {
    lines.push('VARIABLES');
    model.variables.forEach((v, i) => {
      const comma = i < model.variables!.length - 1 ? ',' : '';
      lines.push(`  ${v.name}${comma}  \\* ${v.type}`);
    });
    lines.push('');
  }

  // States as constants
  if (model.states && model.states.length > 0) {
    lines.push('CONSTANTS');
    model.states.forEach(s => {
      lines.push(`  ${s.name}`);
    });
    lines.push('');

    lines.push('States == {' + model.states.map(s => s.name).join(', ') + '}');
    lines.push('');
  }

  // Initial state
  lines.push('Init ==');
  if (model.states?.find(s => s.type === 'initial')) {
    const initial = model.states.find(s => s.type === 'initial')!;
    lines.push(`  /\\ state = ${initial.name}`);
  }
  model.variables?.forEach(v => {
    if (v.initialValue) {
      lines.push(`  /\\ ${v.name} = ${v.initialValue}`);
    }
  });
  lines.push('');

  // Transitions as actions
  if (model.transitions && model.transitions.length > 0) {
    model.transitions.forEach((t, i) => {
      lines.push(`${t.action}_${i} ==`);
      lines.push(`  /\\ state = ${t.from}`);
      if (t.guard) {
        lines.push(`  /\\ ${t.guard.replace(/&&/g, '/\\\\').replace(/\|\|/g, '\\/')}`);
      }
      lines.push(`  /\\ state' = ${t.to}`);
      lines.push('');
    });
  }

  // Next relation
  lines.push('Next ==');
  if (model.transitions && model.transitions.length > 0) {
    model.transitions.forEach((t, i) => {
      const prefix = i === 0 ? '  ' : '  \\/ ';
      lines.push(`${prefix}${t.action}_${i}`);
    });
  } else {
    lines.push('  UNCHANGED <<state>>');
  }
  lines.push('');

  // Invariants
  if (model.invariants && model.invariants.length > 0) {
    lines.push('TypeInvariant ==');
    model.invariants.forEach((inv, i) => {
      const prefix = i === 0 ? '  ' : '  /\\ ';
      lines.push(`${prefix}${inv.expression}`);
    });
    lines.push('');
  }

  // Safety property: no error states reachable
  const errorStates = model.states?.filter(s => s.type === 'error') || [];
  if (errorStates.length > 0) {
    lines.push('Safety ==');
    lines.push(`  state \\notin {${errorStates.map(s => s.name).join(', ')}}`);
    lines.push('');
  }

  // Liveness: eventually reach final state
  const finalStates = model.states?.filter(s => s.type === 'final') || [];
  if (finalStates.length > 0) {
    lines.push('Liveness ==');
    lines.push(`  <>(state \\in {${finalStates.map(s => s.name).join(', ')}})`);
    lines.push('');
  }

  // Spec
  lines.push('Spec == Init /\\ [][Next]_<<state>>');
  lines.push('');
  lines.push('====');

  return lines.join('\n');
}

// Generate Alloy model
function generateAlloy(model: FormalModel): string {
  const lines: string[] = [];

  lines.push('// Alloy model generated from source code');
  lines.push(`module ${model.language}Model`);
  lines.push('');

  // States as signatures
  if (model.states && model.states.length > 0) {
    lines.push('abstract sig State {}');
    model.states.forEach(s => {
      lines.push(`one sig ${s.name} extends State {}`);
    });
    lines.push('');
  }

  // System signature with state
  lines.push('sig System {');
  lines.push('  state: one State,');
  model.variables?.forEach((v, i) => {
    const comma = i < model.variables!.length - 1 ? ',' : '';
    lines.push(`  ${v.name}: one ${v.type === 'number' || v.type === 'int' ? 'Int' : 'univ'}${comma}`);
  });
  lines.push('}');
  lines.push('');

  // Transitions as predicates
  if (model.transitions && model.transitions.length > 0) {
    model.transitions.forEach((t, i) => {
      lines.push(`pred ${t.action}_${i}[s, s': System] {`);
      lines.push(`  s.state = ${t.from}`);
      if (t.guard) {
        lines.push(`  // Guard: ${t.guard}`);
      }
      lines.push(`  s'.state = ${t.to}`);
      lines.push('}');
      lines.push('');
    });
  }

  // Invariants as facts
  if (model.invariants && model.invariants.length > 0) {
    lines.push('fact Invariants {');
    model.invariants.forEach(inv => {
      lines.push(`  // ${inv.expression}`);
      lines.push(`  all s: System | /* ${inv.expression} */`);
    });
    lines.push('}');
    lines.push('');
  }

  // Initial state predicate
  const initialState = model.states?.find(s => s.type === 'initial');
  if (initialState) {
    lines.push('pred init[s: System] {');
    lines.push(`  s.state = ${initialState.name}`);
    lines.push('}');
    lines.push('');
  }

  // Safety assertions
  const errorStates = model.states?.filter(s => s.type === 'error') || [];
  if (errorStates.length > 0) {
    lines.push('assert NoErrorStates {');
    lines.push(`  no s: System | s.state in ${errorStates.map(e => e.name).join(' + ')}`);
    lines.push('}');
    lines.push('');
  }

  // Run command
  lines.push('run {} for 5');

  return lines.join('\n');
}

// Generate Design by Contract specification
function generateContracts(model: FormalModel): string {
  const lines: string[] = [];

  lines.push('# Design by Contract Specification');
  lines.push('');
  lines.push('## Class Invariants');
  lines.push('');

  if (model.invariants && model.invariants.length > 0) {
    model.invariants.forEach(inv => {
      lines.push(`- \`${inv.expression}\` (scope: ${inv.scope}, line: ${inv.line})`);
    });
  } else {
    lines.push('_No class invariants detected_');
  }
  lines.push('');

  lines.push('## State Variables');
  lines.push('');
  if (model.variables && model.variables.length > 0) {
    lines.push('| Variable | Type | Initial Value | Line |');
    lines.push('|----------|------|---------------|------|');
    model.variables.forEach(v => {
      lines.push(`| ${v.name} | ${v.type} | ${v.initialValue || '-'} | ${v.line} |`);
    });
  }
  lines.push('');

  lines.push('## Function Contracts');
  lines.push('');

  if (model.functions && model.functions.length > 0) {
    model.functions.forEach(func => {
      lines.push(`### \`${func.name}(${func.params.map(p => `${p.name}: ${p.type}`).join(', ')}): ${func.returnType}\``);
      lines.push(`**Line:** ${func.line}`);
      lines.push('');

      if (func.preconditions.length > 0) {
        lines.push('**Preconditions:**');
        func.preconditions.forEach(pre => {
          lines.push(`- \`@requires ${pre}\``);
        });
        lines.push('');
      }

      if (func.postconditions.length > 0) {
        lines.push('**Postconditions:**');
        func.postconditions.forEach(post => {
          lines.push(`- \`@ensures ${post}\``);
        });
        lines.push('');
      }

      if (func.modifies.length > 0) {
        lines.push('**Modifies:**');
        lines.push(`- \`@modifies ${func.modifies.join(', ')}\``);
        lines.push('');
      }

      lines.push('---');
      lines.push('');
    });
  } else {
    lines.push('_No functions detected_');
  }

  return lines.join('\n');
}

// Generate State Machine diagram
function generateStateMachine(model: FormalModel): string {
  const lines: string[] = [];

  lines.push('# Finite State Machine');
  lines.push('');

  lines.push('## States');
  lines.push('');
  if (model.states && model.states.length > 0) {
    lines.push('| State | Type | Line |');
    lines.push('|-------|------|------|');
    model.states.forEach(s => {
      const icon = s.type === 'initial' ? '▶' : s.type === 'final' ? '◉' : s.type === 'error' ? '✕' : '○';
      lines.push(`| ${icon} ${s.name} | ${s.type} | ${s.line || '-'} |`);
    });
  }
  lines.push('');

  lines.push('## Transitions');
  lines.push('');
  if (model.transitions && model.transitions.length > 0) {
    lines.push('| From | To | Action | Guard | Line |');
    lines.push('|------|-----|--------|-------|------|');
    model.transitions.forEach(t => {
      lines.push(`| ${t.from} | ${t.to} | ${t.action} | ${t.guard || '-'} | ${t.line || '-'} |`);
    });
  }
  lines.push('');

  // Generate Mermaid diagram
  lines.push('## Mermaid Diagram');
  lines.push('');
  lines.push('```mermaid');
  lines.push('stateDiagram-v2');

  const initialState = model.states?.find(s => s.type === 'initial');
  if (initialState) {
    lines.push(`  [*] --> ${initialState.name}`);
  }

  model.transitions?.forEach(t => {
    if (t.guard) {
      lines.push(`  ${t.from} --> ${t.to}: ${t.action} [${t.guard}]`);
    } else {
      lines.push(`  ${t.from} --> ${t.to}: ${t.action}`);
    }
  });

  model.states?.filter(s => s.type === 'final').forEach(s => {
    lines.push(`  ${s.name} --> [*]`);
  });

  lines.push('```');

  return lines.join('\n');
}

// Generate Petri Net diagram
function generatePetriNetDiagram(model: FormalModel): string {
  const lines: string[] = [];

  lines.push('# Petri Net Model');
  lines.push('');
  lines.push('## Places');
  lines.push('');
  if (model.places && model.places.length > 0) {
    lines.push('| Place | Initial Tokens |');
    lines.push('|-------|----------------|');
    model.places.forEach(p => {
      lines.push(`| ${p.name} | ${p.tokens} |`);
    });
  } else {
    lines.push('_No concurrent operations detected_');
  }
  lines.push('');

  lines.push('## Transitions');
  lines.push('');
  if (model.petriTransitions && model.petriTransitions.length > 0) {
    lines.push('| Transition | Inputs | Outputs | Guard |');
    lines.push('|------------|--------|---------|-------|');
    model.petriTransitions.forEach(t => {
      lines.push(`| ${t.name} | ${t.inputs.join(', ') || '-'} | ${t.outputs.join(', ') || '-'} | ${t.guard || '-'} |`);
    });
  }
  lines.push('');

  // Generate DOT format for visualization
  lines.push('## GraphViz DOT Format');
  lines.push('');
  lines.push('```dot');
  lines.push('digraph PetriNet {');
  lines.push('  rankdir=LR;');
  lines.push('  node [shape=circle]; // Places');

  model.places?.forEach(p => {
    const label = p.tokens > 0 ? `${p.name}\\n(${p.tokens})` : p.name;
    lines.push(`  "${p.name}" [label="${label}"];`);
  });

  lines.push('  node [shape=box]; // Transitions');
  model.petriTransitions?.forEach(t => {
    lines.push(`  "${t.name}";`);
    t.inputs.forEach(input => {
      lines.push(`  "${input}" -> "${t.name}";`);
    });
    t.outputs.forEach(output => {
      lines.push(`  "${t.name}" -> "${output}";`);
    });
  });

  lines.push('}');
  lines.push('```');

  return lines.join('\n');
}

// Detect language from code
function detectLanguage(code: string): SupportedLanguage {
  if (code.includes('<?php')) return 'php';
  if (/^package\s+\w+/.test(code) || /func\s+\w+\(/.test(code)) return 'go';
  if (/:\s*\w+\s*[=\)]/.test(code) && /interface\s+\w+/.test(code)) return 'typescript';
  if (/def\s+\w+.*:/.test(code) && /import\s+\w+/.test(code)) return 'python';
  if (/def\s+\w+/.test(code) && /end\b/.test(code)) return 'ruby';
  return 'javascript';
}

// Main analysis function
function generateFormalModelFromCode(
  code: string,
  modelType: ModelType,
  language?: SupportedLanguage
): FormalModel {
  const detectedLang = language || detectLanguage(code);

  const states = extractStates(code, detectedLang);
  const transitions = extractTransitions(code, detectedLang, states);
  const variables = extractVariables(code, detectedLang);
  const functions = extractFunctions(code, detectedLang);
  const invariants = extractInvariants(code, detectedLang);
  const { places, transitions: petriTransitions } = extractPetriNet(code, detectedLang);

  let specification: string;

  switch (modelType) {
    case 'tlaplus':
      specification = generateTLAPlus({
        type: modelType,
        language: detectedLang,
        states,
        transitions,
        variables,
        functions,
        invariants,
        specification: '',
      });
      break;
    case 'alloy':
      specification = generateAlloy({
        type: modelType,
        language: detectedLang,
        states,
        transitions,
        variables,
        functions,
        invariants,
        specification: '',
      });
      break;
    case 'contracts':
      specification = generateContracts({
        type: modelType,
        language: detectedLang,
        states,
        transitions,
        variables,
        functions,
        invariants,
        specification: '',
      });
      break;
    case 'petri-net':
      specification = generatePetriNetDiagram({
        type: modelType,
        language: detectedLang,
        places,
        petriTransitions,
        specification: '',
      });
      break;
    case 'state-machine':
    default:
      specification = generateStateMachine({
        type: modelType,
        language: detectedLang,
        states,
        transitions,
        specification: '',
      });
      break;
  }

  return {
    type: modelType,
    language: detectedLang,
    states,
    transitions,
    variables,
    functions,
    invariants,
    places,
    petriTransitions,
    specification,
  };
}

export function registerGenerateFormalModelTool(server: McpServer): void {
  server.tool(
    'generate-formal-model',
    'Generate formal models (state machines, TLA+, Alloy, contracts, Petri nets) from source code for verification and analysis',
    {
      code: z.string().describe('Source code to analyze and model'),
      modelType: z.enum(['state-machine', 'tlaplus', 'alloy', 'contracts', 'petri-net'])
        .default('state-machine')
        .describe('Type of formal model to generate'),
      language: z.enum(['javascript', 'typescript', 'python', 'go', 'php', 'ruby'])
        .optional()
        .describe('Programming language (auto-detected if not specified)'),
    },
    async (params) => {
      const validation = validateInput(params.code);
      logToolInvocation('generate-formal-model', {
        modelType: params.modelType,
        language: params.language,
        codeLength: params.code.length,
      }, validation.warnings);

      try {
        const model = generateFormalModelFromCode(
          params.code,
          params.modelType,
          params.language
        );

        // Build summary
        const summary: string[] = [];
        summary.push(`# Formal Model: ${params.modelType.toUpperCase()}`);
        summary.push(`**Language:** ${model.language}`);
        summary.push('');
        summary.push('## Extraction Summary');
        summary.push(`- **States:** ${model.states?.length || 0}`);
        summary.push(`- **Transitions:** ${model.transitions?.length || 0}`);
        summary.push(`- **Variables:** ${model.variables?.length || 0}`);
        summary.push(`- **Functions:** ${model.functions?.length || 0}`);
        summary.push(`- **Invariants:** ${model.invariants?.length || 0}`);
        if (model.places && model.places.length > 0) {
          summary.push(`- **Petri Places:** ${model.places.length}`);
          summary.push(`- **Petri Transitions:** ${model.petriTransitions?.length || 0}`);
        }
        summary.push('');
        summary.push('---');
        summary.push('');
        summary.push(model.specification);

        const result = summary.join('\n');
        logOutput('generate-formal-model', {
          success: true,
          summary: `Generated ${params.modelType} model with ${model.states?.length || 0} states, ${model.transitions?.length || 0} transitions`,
          metrics: {
            states: model.states?.length || 0,
            transitions: model.transitions?.length || 0,
            variables: model.variables?.length || 0,
            functions: model.functions?.length || 0,
            invariants: model.invariants?.length || 0,
          },
          fullOutput: result,
        });

        return {
          content: [{ type: 'text' as const, text: result }],
        };
      } catch (error) {
        const errorMsg = `Error generating formal model: ${error instanceof Error ? error.message : String(error)}`;
        logOutput('generate-formal-model', {
          success: false,
          error: errorMsg,
        });
        return {
          content: [{ type: 'text', text: errorMsg }],
          isError: true,
        };
      }
    }
  );
}
