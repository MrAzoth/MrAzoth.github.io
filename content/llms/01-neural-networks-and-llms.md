---
title: "From Neurons to GPT: How Neural Networks and Large Language Models Actually Work"
date: 2026-02-24
draft: false
---

# From Neurons to GPT: How Neural Networks and Large Language Models Actually Work

There is a lot of hype around LLMs and not enough signal about what is actually happening under the hood. This post tries to fix that. Starting from the absolute basics — a single artificial neuron — we will build up, step by step, to a full understanding of how a model like GPT works. Every concept is grounded in real code and real math.

---

## Part 1: The Artificial Neuron

Everything in deep learning starts with one object: the neuron.

A biological neuron receives signals through its dendrites, processes them in the cell body, and fires an output through its axon. The artificial version does the same thing, just with numbers:

```
Inputs x₁, x₂, ..., xₙ  →  weighted sum z = Σ wᵢxᵢ + b  →  activation f(z)  →  output
```

The three components are:

- **Weights (w)** — how much each input matters
- **Bias (b)** — a baseline offset
- **Activation function f** — a non-linear transformation applied to the weighted sum

Here is the implementation of a single neuron from scratch using only NumPy:

```python
import numpy as np

class Neuron:
    def __init__(self, num_inputs):
        # Small random weights — avoid symmetry breaking issues
        self.weights = np.random.randn(num_inputs) * 0.1
        self.bias = 0.0

    def forward(self, x, activation='sigmoid'):
        # Weighted sum: z = w·x + b
        z = np.dot(self.weights, x) + self.bias

        if activation == 'sigmoid':
            return 1 / (1 + np.exp(-z))
        elif activation == 'relu':
            return max(0, z)
        elif activation == 'tanh':
            return np.tanh(z)
        else:
            return z  # linear


# Example: neuron with 3 inputs
neuron = Neuron(num_inputs=3)
test_input = np.array([1.0, 2.0, 3.0])

# Weights: [ 0.00593647 -0.03491544  0.09868344], Bias: 0.0
# z = 0.006*1 - 0.035*2 + 0.099*3 = 0.232
# sigmoid(0.232) = 0.5578
output = neuron.forward(test_input, activation='sigmoid')
print(f"Output: {output:.4f}")  # → 0.5578
```

Concrete numerical example:
```
x = [2, 3],  w = [0.5, -0.3],  b = 1.0

z = (0.5 × 2) + (-0.3 × 3) + 1.0
  = 1.0 - 0.9 + 1.0
  = 1.1

output = sigmoid(1.1) ≈ 0.75
```

This alone does nothing interesting. The power comes from stacking thousands of neurons into layers.

---

## Part 2: Activation Functions — Why Non-Linearity Is Everything

Without activation functions, a neural network of any depth collapses into a single linear transformation. You can stack fifty layers of matrix multiplications, but:

```
y = W₃(W₂(W₁x)) = (W₃W₂W₁)x = Wx
```

The whole thing reduces to one matrix. Activation functions break this by introducing non-linearity between layers.

```python
import numpy as np
import matplotlib.pyplot as plt

def sigmoid(z):
    return 1 / (1 + np.exp(-z))

def relu(z):
    return np.maximum(0, z)

def gelu(z):
    # Approximation used in GPT — smoother than ReLU
    return 0.5 * z * (1 + np.tanh(np.sqrt(2/np.pi) * (z + 0.044715 * z**3)))

def leaky_relu(z, alpha=0.01):
    return np.where(z > 0, z, alpha * z)

z = np.linspace(-5, 5, 200)
```

### Sigmoid — `σ(z) = 1 / (1 + e^(-z))`

Output between 0 and 1. Good for binary classification and gates (LSTM). Problem: for large positive or negative inputs the gradient approaches zero — the *vanishing gradient* problem.

### ReLU — `ReLU(z) = max(0, z)`

Dominant in modern networks. No saturation for positive values, so gradients flow cleanly. Risk: "dying neurons" — if a neuron's input is consistently negative, its gradient is always zero and it stops learning. Leaky ReLU uses `αz` instead of zero for negative inputs.

### GELU — Gaussian Error Linear Unit

```
GELU(z) ≈ 0.5z · (1 + tanh(√(2/π) · (z + 0.044715z³)))
```

Used in GPT-2, GPT-3, BERT. Smooth version of ReLU that allows small negative values through. The smooth transition (no hard zero cutoff) empirically improves performance in transformer architectures.

```python
# At z = -0.5:
# ReLU(-0.5)  = 0.0        (hard cutoff)
# GELU(-0.5)  ≈ -0.154     (small negative passes through)
# Sigmoid(-0.5) ≈ 0.378    (squashed to (0,1))

print(f"ReLU(-0.5) = {relu(-0.5):.3f}")
print(f"GELU(-0.5) = {gelu(-0.5):.3f}")
print(f"Sigmoid(-0.5) = {sigmoid(-0.5):.3f}")
```

Output:
```
ReLU(-0.5) = 0.000
GELU(-0.5) = -0.154
Sigmoid(-0.5) = 0.378
```

---

## Part 3: Forward Propagation — Data Flows Through Layers

A multilayer network is a chain of transformations. For each layer `l`:

```
zₗ = Wₗ · aₗ₋₁ + bₗ       (linear)
aₗ = f(zₗ)                  (non-linear activation)
```

Where `a₀ = x` (raw input). Full implementation:

```python
class NeuralNetwork:
    def __init__(self, layer_sizes):
        """
        layer_sizes: e.g. [2, 4, 3, 1]
        → 2 inputs, hidden layers of 4 and 3, 1 output
        """
        self.weights = []
        self.biases = []
        self.num_layers = len(layer_sizes) - 1

        for i in range(self.num_layers):
            n_in, n_out = layer_sizes[i], layer_sizes[i+1]
            # Xavier initialization: std = sqrt(2 / (n_in + n_out))
            W = np.random.randn(n_out, n_in) * np.sqrt(2.0 / (n_in + n_out))
            b = np.zeros(n_out)
            self.weights.append(W)
            self.biases.append(b)

    def forward(self, x):
        activations = [x]  # save all activations for backprop
        a = x

        for i, (W, b) in enumerate(zip(self.weights, self.biases)):
            z = np.dot(W, a) + b
            # ReLU for hidden layers, sigmoid for output
            a = relu(z) if i < self.num_layers - 1 else sigmoid(z)
            activations.append(a)

        return a, activations
```

Trace through a `[2, 4, 3, 1]` network with input `[0.5, -0.3]`:

```
Input:    [0.5, -0.3]               shape: (2,)

Layer 1:  z = W₁·x + b₁            shape: (4,)  → e.g. [-0.655, 0.407, -0.111, 0.247]
          a₁ = ReLU(z)              shape: (4,)  → [0.0, 0.407, 0.0, 0.247]

Layer 2:  z = W₂·a₁ + b₂           shape: (3,)  → [0.373, -0.249, 0.365]
          a₂ = ReLU(z)              shape: (3,)  → [0.373, 0.0, 0.365]

Layer 3:  z = W₃·a₂ + b₃           shape: (1,)  → [0.125]
          output = sigmoid(z)       shape: (1,)  → [0.531]
```

ReLU zeros out negative activations — this is visible in layers 1 and 2. The output layer uses sigmoid to squash the prediction to (0, 1).

---

## Part 4: Loss Functions — Quantifying Error

The loss function measures how wrong the current predictions are. Training is the process of minimizing it.

```python
def mean_squared_error(y_true, y_pred):
    return np.mean((y_true - y_pred) ** 2)

def binary_cross_entropy(y_true, y_pred, epsilon=1e-15):
    y_pred = np.clip(y_pred, epsilon, 1 - epsilon)
    return -np.mean(y_true * np.log(y_pred) + (1 - y_true) * np.log(1 - y_pred))

def categorical_cross_entropy(y_true, y_pred, epsilon=1e-15):
    # This is what GPT uses: -Σ y_true · log(y_pred)
    y_pred = np.clip(y_pred, epsilon, 1)
    return -np.sum(y_true * np.log(y_pred))
```

**MSE for regression:**
```python
y_true = np.array([1.0, 2.0, 3.0, 4.0, 5.0])
y_pred = np.array([1.1, 2.2, 2.8, 4.1, 4.9])

mse = mean_squared_error(y_true, y_pred)
# MSE = 0.022,  RMSE = 0.148
```

**Categorical Cross-Entropy — what GPT optimizes every single step:**

```python
# Vocabulary size = 5, correct token is index 2
y_true = np.array([0, 0, 1, 0, 0])  # one-hot

y_pred_good = np.array([0.05, 0.05, 0.80, 0.05, 0.05])
y_pred_bad  = np.array([0.30, 0.30, 0.10, 0.20, 0.10])

cce_good = categorical_cross_entropy(y_true, y_pred_good)
cce_bad  = categorical_cross_entropy(y_true, y_pred_bad)

print(f"Good prediction CCE: {cce_good:.4f}")  # → 0.2231
print(f"Bad  prediction CCE: {cce_bad:.4f}")   # → 2.3026

# Perplexity = exp(loss) — the standard LM metric
print(f"Good perplexity: {np.exp(cce_good):.2f}")   # → 1.25
print(f"Bad  perplexity: {np.exp(cce_bad):.2f}")    # → 10.00
```

A perplexity of 1.25 means the model was nearly certain. A perplexity of 10 means it was as uncertain as if choosing among 10 equally likely tokens.

---

## Part 5: Backpropagation — Computing Gradients via Chain Rule

Forward propagation gives predictions and a loss. Backpropagation computes the gradient of that loss with respect to every weight — it answers "if I change this weight by a tiny amount, how much does the loss change?"

The math is the **chain rule**:

```
Loss L → output a₂ → z₂ = W₂·a₁+b₂ → a₁ → z₁ = W₁·x+b₁

∂L/∂W₁ = (∂L/∂a₂) · (∂a₂/∂z₂) · (∂z₂/∂a₁) · (∂a₁/∂z₁) · (∂z₁/∂W₁)
```

Key derivatives:
```python
def sigmoid_derivative(z):
    s = sigmoid(z)
    return s * (1 - s)        # σ'(z) = σ(z)·(1−σ(z))

def relu_derivative(z):
    return (z > 0).astype(float)   # 1 if z > 0, else 0
```

Full backpropagation:

```python
def backward(self, y_true, activations):
    gradients_W = [None] * self.num_layers
    gradients_b = [None] * self.num_layers

    y_pred = activations[-1]
    # ∂L/∂a for MSE loss
    delta = (y_pred - y_true)

    for layer in range(self.num_layers - 1, -1, -1):
        a_prev = activations[layer]

        # ∂L/∂W = delta · a_prev^T
        gradients_W[layer] = np.outer(delta, a_prev)
        # ∂L/∂b = delta
        gradients_b[layer] = delta

        if layer > 0:
            # Propagate delta back: ∂L/∂a_prev = W^T · delta
            delta = np.dot(self.weights[layer].T, delta)
            # Multiply by activation derivative (ReLU for hidden layers)
            z_prev = np.dot(self.weights[layer-1], activations[layer-1]) + self.biases[layer-1]
            delta = delta * relu_derivative(z_prev)

    return gradients_W, gradients_b
```

Trace for a `[2, 3, 1]` network with `y_pred=0.5`, `y_true=1.0`:

```
delta (output) = 0.5 - 1.0 = -0.5

Layer 2:  ∂L/∂W₂ = outer([-0.5], a₁)   shape: (1, 3)
          ∂L/∂b₂ = [-0.5]
          delta propagated back = W₂ᵀ · [-0.5]   shape: (3,)

Layer 1:  ∂L/∂W₁ = outer(delta, x)      shape: (3, 2)
          ∂L/∂b₁ = delta
```

---

## Part 6: Gradient Descent — Updating Weights

Once gradients are computed, update each weight in the direction that reduces the loss:

```
w_new = w_old - α · ∂L/∂w
```

Where `α` is the learning rate.

```python
def train_network(nn, X_train, y_train, learning_rate=0.01, epochs=100):
    losses = []

    for epoch in range(epochs):
        epoch_loss = 0

        for x, y_true in zip(X_train, y_train):
            # Forward
            y_pred, activations = nn.forward(x)
            epoch_loss += mean_squared_error(y_true, y_pred)

            # Backward
            grad_W, grad_b = nn.backward(y_true, activations)

            # Gradient descent update
            for layer in range(nn.num_layers):
                nn.weights[layer] -= learning_rate * grad_W[layer]
                nn.biases[layer]  -= learning_rate * grad_b[layer]

        losses.append(epoch_loss / len(X_train))

    return losses
```

**XOR problem** — the classic test for non-linear networks (linear models cannot solve XOR):

```python
X_train = np.array([[0,0], [0,1], [1,0], [1,1]])
y_train = np.array([[0], [1], [1], [0]])

nn_xor = NeuralNetwork(layer_sizes=[2, 4, 1])
losses = train_network(nn_xor, X_train, y_train, learning_rate=0.5, epochs=1000)

# After training:
# [0,0] → 0.032   ✓   (target: 0)
# [0,1] → 0.961   ✓   (target: 1)
# [1,0] → 0.961   ✓   (target: 1)
# [1,1] → 0.043   ✓   (target: 0)
# Loss: 0.25 → 0.004 (98% reduction)
```

---

## Part 7: Tokenization — Text Into Numbers

Neural networks work with numbers. The first step in any language model is converting text into integers (tokens).

### Character-level tokenizer (educational baseline):

```python
class SimpleCharTokenizer:
    def __init__(self):
        self.char2idx = {}
        self.idx2char = {}
        self.vocab_size = 0

    def build_vocabulary(self, text):
        unique_chars = sorted(set(text))
        for idx, char in enumerate(unique_chars):
            self.char2idx[char] = idx
            self.idx2char[idx]  = char
        self.vocab_size = len(unique_chars)

    def encode(self, text):
        return [self.char2idx.get(char, 0) for char in text]

    def decode(self, ids):
        return ''.join(self.idx2char.get(i, '?') for i in ids)

tokenizer = SimpleCharTokenizer()
tokenizer.build_vocabulary("Hello, World!")
# vocab_size = 10 unique chars

print(tokenizer.encode("Hello"))  # → [3, 4, 7, 7, 8]
print(tokenizer.decode([3,4,7,7,8]))  # → "Hello"
```

### GPT-2 BPE tokenizer (production):

```python
import tiktoken

enc = tiktoken.get_encoding("gpt2")

text = "Hello, World! Let's tokenize this text."
tokens = enc.encode(text)
# → [15496, 11, 1588, 0, 3914, 338, 11241, 1096, 428, 2420, 13]

decoded = enc.decode(tokens)
# → "Hello, World! Let's tokenize this text."

# Subword example — how "tokenization" splits:
word = "tokenization"
for tok_id in enc.encode(word):
    print(f"  [{tok_id}] = '{enc.decode([tok_id])}'")
# [30001] = 'token'
# [1634]  = 'ization'
```

GPT-2 vocabulary: **50,257 tokens**. BPE starts from characters and iteratively merges the most frequent adjacent pairs until it reaches the target vocabulary size. The result represents common words as single tokens and rare words as subword sequences.

---

## Part 8: Embeddings — Tokens Into Vectors

Token IDs are arbitrary integers with no mathematical relationship. Embeddings fix this by mapping each ID to a learnable dense vector.

```python
import torch
import torch.nn as nn

class TokenEmbedding(nn.Module):
    def __init__(self, vocab_size, embed_dim):
        super().__init__()
        # Lookup table: (vocab_size, embed_dim)
        self.token_embedding = nn.Embedding(vocab_size, embed_dim)
        self.embed_dim = embed_dim

    def forward(self, token_ids):
        # Input:  (batch_size, seq_len)       — integers
        # Output: (batch_size, seq_len, d)    — floats
        return self.token_embedding(token_ids)


class PositionalEmbedding(nn.Module):
    def __init__(self, max_seq_len, embed_dim):
        super().__init__()
        # Each position gets its own learnable vector
        self.pos_embedding = nn.Embedding(max_seq_len, embed_dim)

    def forward(self, token_embeddings):
        batch_size, seq_len, _ = token_embeddings.shape
        positions = torch.arange(seq_len).unsqueeze(0)  # (1, seq_len)
        pos_emb = self.pos_embedding(positions)          # (1, seq_len, d)
        # Broadcasting: add position info to every item in the batch
        return token_embeddings + pos_emb
```

**Final embedding = Token Embedding + Positional Embedding**

```python
vocab_size = 1000
embed_dim  = 64
seq_len    = 10
batch_size = 2

token_emb = TokenEmbedding(vocab_size, embed_dim)
pos_emb   = PositionalEmbedding(seq_len, embed_dim)

token_ids = torch.randint(0, vocab_size, (batch_size, seq_len))
x = token_emb(token_ids)    # (2, 10, 64)
x = pos_emb(x)              # (2, 10, 64) — same shape, position added

print(f"Embedding output shape: {x.shape}")  # torch.Size([2, 10, 64])
```

After training, the embedding space develops geometric structure:
```
embedding("king") - embedding("man") + embedding("woman") ≈ embedding("queen")
```

This arithmetic works because the model learns to encode semantic relationships as directions in vector space.

---

## Part 9: Self-Attention — Every Token Sees Every Other Token

Self-attention allows each token to look at all others in the sequence and decide which ones are relevant to its representation.

Classic example: *"The bank of the river"* — "bank" is ambiguous, but by attending to "river", the model resolves it to a riverbank.

**Q, K, V framework:**

```python
class SelfAttention(nn.Module):
    def __init__(self, embed_dim, head_dim):
        super().__init__()
        self.W_query = nn.Linear(embed_dim, head_dim, bias=False)
        self.W_key   = nn.Linear(embed_dim, head_dim, bias=False)
        self.W_value = nn.Linear(embed_dim, head_dim, bias=False)
        self.head_dim = head_dim
        self.scale = head_dim ** -0.5  # 1/√dₖ

    def forward(self, x):
        # x: (batch, seq_len, embed_dim)

        Q = self.W_query(x)   # "What am I looking for?"
        K = self.W_key(x)     # "What do I offer?"
        V = self.W_value(x)   # "What is my content?"

        # Attention scores: how much does each token attend to each other?
        # Shape: (batch, seq_len, seq_len)
        scores = torch.matmul(Q, K.transpose(-2, -1)) * self.scale

        # Causal mask: token i cannot attend to tokens j > i
        seq_len = x.size(1)
        mask = torch.triu(torch.ones(seq_len, seq_len), diagonal=1).bool()
        scores = scores.masked_fill(mask, float('-inf'))

        # Softmax → probability distribution over positions
        weights = torch.softmax(scores, dim=-1)

        # Weighted sum of values
        output = torch.matmul(weights, V)
        return output, weights
```

**Mathematical form:**

```
Attention(Q, K, V) = softmax(QKᵀ / √dₖ) · V
```

The `√dₖ` scaling prevents dot products from growing large in high dimensions — without it, softmax would collapse to near-one-hot distributions, making gradients vanish.

**Causal masking** enforces autoregression. The mask sets the upper triangle to -∞ before softmax, so those positions get zero attention after the softmax exponential:

```
Mask (4 tokens):           Attention weights (example):
[0, -∞, -∞, -∞]           [1.00, 0.00, 0.00, 0.00]
[0,  0, -∞, -∞]    →      [0.60, 0.40, 0.00, 0.00]
[0,  0,  0, -∞]           [0.40, 0.35, 0.25, 0.00]
[0,  0,  0,  0]           [0.25, 0.25, 0.25, 0.25]
```

---

## Part 10: Multi-Head Attention — Multiple Simultaneous Perspectives

A single attention head captures one type of relationship. Multiple heads run in parallel, each with independent projections:

```python
class MultiHeadAttention(nn.Module):
    def __init__(self, embed_dim, num_heads):
        super().__init__()
        assert embed_dim % num_heads == 0
        self.num_heads = num_heads
        self.head_dim  = embed_dim // num_heads
        self.scale     = self.head_dim ** -0.5

        # Single projection matrices (more efficient than separate per-head)
        self.W_query = nn.Linear(embed_dim, embed_dim, bias=False)
        self.W_key   = nn.Linear(embed_dim, embed_dim, bias=False)
        self.W_value = nn.Linear(embed_dim, embed_dim, bias=False)
        self.W_out   = nn.Linear(embed_dim, embed_dim, bias=False)

    def forward(self, x, mask=None):
        batch_size, seq_len, embed_dim = x.shape

        Q = self.W_query(x)
        K = self.W_key(x)
        V = self.W_value(x)

        # Reshape to separate heads
        # (batch, seq_len, embed_dim) → (batch, heads, seq_len, head_dim)
        def split_heads(t):
            t = t.view(batch_size, seq_len, self.num_heads, self.head_dim)
            return t.transpose(1, 2)

        Q, K, V = split_heads(Q), split_heads(K), split_heads(V)

        # Attention per head
        scores = torch.matmul(Q, K.transpose(-2, -1)) * self.scale
        if mask is not None:
            scores = scores.masked_fill(mask == 0, float('-inf'))
        weights = torch.softmax(scores, dim=-1)
        out = torch.matmul(weights, V)

        # Merge heads: (batch, heads, seq_len, head_dim) → (batch, seq_len, embed_dim)
        out = out.transpose(1, 2).contiguous().view(batch_size, seq_len, embed_dim)

        return self.W_out(out), weights


# GPT-2 small: embed_dim=768, num_heads=12 → head_dim=64
mha = MultiHeadAttention(embed_dim=768, num_heads=12)
x = torch.randn(2, 10, 768)     # batch=2, seq=10, dim=768
out, attn = mha(x)
print(f"Output shape:  {out.shape}")   # (2, 10, 768)
print(f"Attention map: {attn.shape}")  # (2, 12, 10, 10)
```

Each head independently learns a different type of relationship. In trained models, some heads have been shown to specialize in syntactic structure (subject–verb), others in coreference (pronoun → antecedent), others in local context.

---

## Part 11: Feed-Forward Network and the Transformer Block

After attention aggregates information across positions, the FFN processes each token independently with a non-linear transformation.

```python
class FeedForwardGELU(nn.Module):
    """FFN with GELU activation — the version used in GPT-2/3"""

    def __init__(self, embed_dim, hidden_dim, dropout=0.1):
        super().__init__()
        # Expand: embed_dim → 4 * embed_dim
        self.linear1 = nn.Linear(embed_dim, hidden_dim)
        # Compress: 4 * embed_dim → embed_dim
        self.linear2 = nn.Linear(hidden_dim, embed_dim)
        self.dropout  = nn.Dropout(dropout)

    def forward(self, x):
        x = self.linear1(x)
        x = F.gelu(x)           # GELU instead of ReLU
        x = self.dropout(x)
        x = self.linear2(x)
        return self.dropout(x)
```

The **Transformer Block** combines attention and FFN with residual connections and layer normalization:

```python
class TransformerBlock(nn.Module):
    def __init__(self, embed_dim, num_heads, hidden_dim, dropout=0.1):
        super().__init__()
        self.attention    = MultiHeadAttention(embed_dim, num_heads)
        self.feed_forward = FeedForwardGELU(embed_dim, hidden_dim, dropout)
        self.ln1     = nn.LayerNorm(embed_dim)
        self.ln2     = nn.LayerNorm(embed_dim)
        self.dropout = nn.Dropout(dropout)

    def forward(self, x, mask=None):
        # Sub-layer 1: attention with residual
        # Pre-norm: LayerNorm BEFORE the operation (more stable than post-norm)
        attn_out, _ = self.attention(self.ln1(x), mask)
        x = x + self.dropout(attn_out)    # residual connection

        # Sub-layer 2: FFN with residual
        ff_out = self.feed_forward(self.ln2(x))
        x = x + ff_out                    # residual connection

        return x
```

**Residual connections** (`x = x + sublayer(x)`) are critical for training deep networks. Gradients flow directly through the addition, ensuring that even early layers receive usable signals. GPT-3 has 96 layers — without residuals, gradients would vanish long before reaching layer 1.

**Pre-norm vs post-norm**: the original transformer (2017) applied LayerNorm after the residual addition (post-norm). Modern architectures including GPT-2/3 use pre-norm (LayerNorm before the sublayer), which is more stable and allows higher learning rates.

```python
# Verify shapes
block = TransformerBlock(embed_dim=256, num_heads=8, hidden_dim=1024)
x = torch.randn(2, 16, 256)      # batch=2, seq=16, dim=256
out = block(x)
print(f"Input:  {x.shape}")      # torch.Size([2, 16, 256])
print(f"Output: {out.shape}")    # torch.Size([2, 16, 256]) — same shape always
```

The output has the same shape as the input. This is fundamental to how stacking works: each transformer block is a function from `(batch, seq_len, d)` → `(batch, seq_len, d)`, so you can stack as many as you want.

---

## Part 12: The Complete GPT Model

Stacking N transformer blocks on top of an embedding layer:

```python
class GPT(nn.Module):
    def __init__(self, vocab_size, embed_dim, num_heads, num_layers,
                 max_seq_len, hidden_dim, dropout=0.1):
        super().__init__()
        self.max_seq_len = max_seq_len

        # Embeddings
        self.token_embedding    = nn.Embedding(vocab_size, embed_dim)
        self.position_embedding = nn.Embedding(max_seq_len, embed_dim)
        self.embed_dropout      = nn.Dropout(dropout)

        # Stack of transformer blocks
        self.transformer_blocks = nn.ModuleList([
            TransformerBlock(embed_dim, num_heads, hidden_dim, dropout)
            for _ in range(num_layers)
        ])

        # Final layer norm + language model head
        self.ln_final = nn.LayerNorm(embed_dim)
        self.head     = nn.Linear(embed_dim, vocab_size, bias=False)

        # Weight initialization
        self.apply(self._init_weights)

    def _init_weights(self, module):
        if isinstance(module, (nn.Linear, nn.Embedding)):
            module.weight.data.normal_(mean=0.0, std=0.02)
            if isinstance(module, nn.Linear) and module.bias is not None:
                module.bias.data.zero_()

    def forward(self, token_ids):
        batch_size, seq_len = token_ids.shape
        assert seq_len <= self.max_seq_len

        # Token + positional embeddings
        positions = torch.arange(seq_len, device=token_ids.device).unsqueeze(0)
        x = self.token_embedding(token_ids) + self.position_embedding(positions)
        x = self.embed_dropout(x)

        # Build causal mask once
        mask = torch.tril(torch.ones(seq_len, seq_len, device=x.device)).unsqueeze(0).unsqueeze(0)

        # Pass through all transformer blocks
        for block in self.transformer_blocks:
            x = block(x, mask)

        x = self.ln_final(x)

        # Project to vocabulary — output is logits for next token
        logits = self.head(x)   # (batch, seq_len, vocab_size)
        return logits
```

**GPT-2 architecture in numbers:**

```python
# GPT-2 Small
gpt2_small = GPT(
    vocab_size  = 50257,
    embed_dim   = 768,
    num_heads   = 12,
    num_layers  = 12,
    max_seq_len = 1024,
    hidden_dim  = 3072    # 4 × 768
)

total_params = sum(p.numel() for p in gpt2_small.parameters())
print(f"GPT-2 Small parameters: {total_params:,}")  # → ~117,000,000
```

| Variant | Parameters | Layers | Heads | d_model | FFN dim |
|---------|-----------|--------|-------|---------|---------|
| Small   | 117M      | 12     | 12    | 768     | 3072    |
| Medium  | 345M      | 24     | 16    | 1024    | 4096    |
| Large   | 762M      | 36     | 20    | 1280    | 5120    |
| XL      | 1.5B      | 48     | 25    | 1600    | 6400    |

GPT-3 scales this to 96 layers, 96 heads, `d=12288` → **175B parameters**.

---

## Part 13: Training — Next-Token Prediction

GPT is trained with a single objective: predict the next token.

```python
class GPTDataset(Dataset):
    def __init__(self, text, tokenizer, max_seq_len):
        self.max_seq_len = max_seq_len
        # Character-level for this example
        self.char_to_idx = {ch: i for i, ch in enumerate(sorted(set(text)))}
        self.idx_to_char = {i: ch for ch, i in self.char_to_idx.items()}
        self.vocab_size  = len(self.char_to_idx)
        self.token_ids   = [self.char_to_idx[ch] for ch in text]

    def __len__(self):
        return len(self.token_ids) - self.max_seq_len

    def __getitem__(self, idx):
        chunk = self.token_ids[idx : idx + self.max_seq_len + 1]
        # input  = chunk[:-1]   → tokens 0..N-1
        # target = chunk[1:]    → tokens 1..N (shifted by 1)
        return (torch.tensor(chunk[:-1], dtype=torch.long),
                torch.tensor(chunk[1:],  dtype=torch.long))


def train_gpt(model, train_loader, optimizer, device, num_epochs):
    model.train()
    losses = []

    for epoch in range(num_epochs):
        epoch_loss = 0.0

        for input_ids, target_ids in train_loader:
            input_ids  = input_ids.to(device)
            target_ids = target_ids.to(device)

            optimizer.zero_grad()

            # Forward pass → logits of shape (batch, seq_len, vocab_size)
            logits = model(input_ids)

            # Flatten for cross-entropy:
            # logits:  (batch * seq_len, vocab_size)
            # targets: (batch * seq_len,)
            loss = F.cross_entropy(
                logits.view(-1, logits.size(-1)),
                target_ids.view(-1)
            )

            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)  # gradient clipping
            optimizer.step()
            epoch_loss += loss.item()

        avg_loss = epoch_loss / len(train_loader)
        losses.append(avg_loss)
        print(f"Epoch {epoch+1}: loss={avg_loss:.4f}, perplexity={np.exp(avg_loss):.2f}")

    return losses
```

The training objective:

```
Loss = -(1/n) Σᵢ log P(tᵢ | t₁, ..., tᵢ₋₁)
```

Every token in every sequence contributes to the loss simultaneously (thanks to causal masking). This makes data utilization very efficient — a single forward pass over a sequence of length N generates N training signals.

---

## Part 14: Text Generation Strategies

At inference time, the model outputs a probability distribution over the vocabulary. Sampling strategy has a major effect on output quality.

```python
def generate_text(model, dataset, start_text, max_new_tokens=100,
                  method='temperature', temperature=1.0, top_k=None, top_p=None):
    model.eval()

    token_ids = [dataset.char_to_idx.get(ch, 0) for ch in start_text]
    generated  = torch.tensor([token_ids], dtype=torch.long).to(device)

    with torch.no_grad():
        for _ in range(max_new_tokens):
            logits     = model(generated[:, -model.max_seq_len:])
            next_logits = logits[:, -1, :]    # only the last position

            if method == 'greedy':
                # Always pick the highest probability token
                next_token = torch.argmax(next_logits, dim=-1, keepdim=True)

            elif method == 'temperature':
                # Scale logits by 1/T, then sample
                probs = F.softmax(next_logits / temperature, dim=-1)
                next_token = torch.multinomial(probs, num_samples=1)

            elif method == 'top_k':
                # Keep only top K tokens, renormalize, sample
                top_k_logits, top_k_idx = torch.topk(next_logits, top_k)
                probs = F.softmax(top_k_logits / temperature, dim=-1)
                idx   = torch.multinomial(probs, num_samples=1)
                next_token = top_k_idx.gather(-1, idx)

            elif method == 'top_p':
                # Keep smallest set with cumulative prob ≥ P
                sorted_logits, sorted_idx = torch.sort(next_logits, descending=True)
                probs = F.softmax(sorted_logits / temperature, dim=-1)
                cumsum = torch.cumsum(probs, dim=-1)
                mask   = cumsum < top_p
                mask[..., 0] = True                       # always keep at least one
                sorted_logits[~mask] = float('-inf')
                probs      = F.softmax(sorted_logits / temperature, dim=-1)
                idx        = torch.multinomial(probs, num_samples=1)
                next_token = sorted_idx.gather(-1, idx)

            generated = torch.cat([generated, next_token], dim=1)

    ids = generated[0].tolist()
    return ''.join(dataset.idx_to_char.get(i, '?') for i in ids)
```

**Temperature effect:**
```
temperature=0.1 (near-deterministic):
  "the" → 99% probability → always picks "the"

temperature=1.0 (default):
  "the" → 45%, "a" → 30%, "this" → 15%, ... → varied output

temperature=1.5 (creative/chaotic):
  probabilities flatten → more surprising but less coherent
```

In production, GPT-3.5/4 typically use `temperature=0.7` + `top_p=0.9` for a balance between coherence and variety.

---

## Part 15: Fine-Tuning for Classification and Instruction Following

The pre-trained model's weights encode general language understanding. Fine-tuning adapts them.

### Classification Head

```python
class GPTForClassification(nn.Module):
    def __init__(self, base_model, num_classes=2, pooling='mean'):
        super().__init__()
        self.base_model = base_model
        self.pooling    = pooling
        self.dropout    = nn.Dropout(0.1)
        self.classifier = nn.Linear(base_model.embed_dim, num_classes)

    def forward(self, input_ids):
        # Get hidden states from base model
        # We need to intercept before the LM head
        # (simplified: using logits as proxy here)
        hidden = self.base_model.get_hidden_states(input_ids)  # (batch, seq, d)

        # Pool across sequence
        if self.pooling == 'mean':
            pooled = hidden.mean(dim=1)     # (batch, d)
        elif self.pooling == 'last':
            pooled = hidden[:, -1, :]       # (batch, d) — last token
        elif self.pooling == 'cls':
            pooled = hidden[:, 0, :]        # (batch, d) — first token

        return self.classifier(self.dropout(pooled))  # (batch, num_classes)
```

### Instruction Fine-Tuning Format

The format used for ChatGPT, Claude, and similar models:

```python
class InstructionDataset(Dataset):
    def __init__(self, data, tokenizer, max_length=512):
        self.data       = data
        self.tokenizer  = tokenizer
        self.max_length = max_length

    def format_example(self, item):
        # Format: instruction + optional input → output
        if item.get('input', ''):
            prompt = (f"### Instruction:\n{item['instruction']}\n\n"
                      f"### Input:\n{item['input']}\n\n"
                      f"### Response:\n{item['output']}")
        else:
            prompt = (f"### Instruction:\n{item['instruction']}\n\n"
                      f"### Response:\n{item['output']}")
        return prompt

    def __getitem__(self, idx):
        text       = self.format_example(self.data[idx])
        token_ids  = self.tokenizer.encode(text)[:self.max_length]
        return torch.tensor(token_ids, dtype=torch.long)
```

The loss is computed only on the response tokens (not the instruction), teaching the model to follow the format without penalizing the instruction preamble.

---

## Putting It All Together

The chain from neuron to GPT:

| Component | Implementation | Purpose |
|-----------|---------------|---------|
| `Neuron` | `z = w·x + b; f(z)` | Basic processing unit |
| `Activation` | ReLU, GELU, Sigmoid | Non-linearity |
| `NeuralNetwork` | `forward()`, `backward()` | Multilayer composition |
| `GradientDescent` | `w -= lr * grad` | Learning from error |
| `SimpleCharTokenizer` | `char2idx`, `idx2char` | Text → integers |
| `TokenEmbedding` | `nn.Embedding(V, d)` | Integers → dense vectors |
| `PositionalEmbedding` | `nn.Embedding(L, d)` | Encodes token order |
| `SelfAttention` | `softmax(QKᵀ/√dₖ)·V` | Token-to-token context |
| `MultiHeadAttention` | h parallel attention heads | Multiple relationship types |
| `FeedForwardGELU` | `W₂·GELU(W₁·x)` | Non-linear per-position transform |
| `TransformerBlock` | Attention + FFN + residuals | Full processing layer |
| `GPT` | N × TransformerBlock + LM head | Complete language model |
| `GPTDataset` | `input=tokens[:-1], target=tokens[1:]` | Next-token prediction data |
| `train_gpt` | Adam, cross-entropy, causal mask | Pre-training loop |
| `generate_text` | temperature / top-k / top-p | Autoregressive generation |

What makes GPT feel intelligent is that predicting the next token of a 500 billion token corpus of human knowledge, at sufficient scale, requires the model to internalize an enormous amount about how the world works. The loss function is simple. The architecture is elegant. The emergent behavior is surprising even to the people who built it.
