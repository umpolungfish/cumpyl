# CA-Based Packer - Distilled CA Engine Design

This document distills the key concepts from the `l8burd` CA implementation that are relevant and adaptable for the CA-based packer project, focusing on creating a simple, efficient, and deterministic PRNG using Cellular Automata.

## Core Concepts from `l8burd` to Adapt

1.  **Deterministic Evolution:** The CA in `l8burd` evolves based on a set of rules applied to cell states and their neighbors. This deterministic nature is crucial for our packer: the same initial state (seed) must always produce the same sequence of masks.
2.  **External Seeding:** `l8burd` uses the machine's IP address (`ip_to_coords`) to determine a specific cell's initial state. For the packer, we will adapt this concept to use the encryption key (and potentially the block index) to seed the initial configuration of our CA.
3.  **Rule Application:** The `apply_rule` function determines the next state of a cell based on its current state and the number of live neighbors. This is the core computational unit of the CA.
4.  **State Transition:** The process of calculating the `next_state` for all cells and then updating the `current_state` ensures synchronous evolution, which is important for predictability.

## Simplified CA Engine Design for Packer

We will implement a much simpler CA, likely 1D, to function as a PRNG within the packer.

### 1. CA Type & Rule

*   **Type:** 1-Dimensional Cellular Automaton.
*   **Rule:** Use a well-known complex rule like **Rule 30**.
    *   **Rule 30 Definition:** For a cell `C` with left neighbor `L` and right neighbor `R`, the next state `C'` is determined by `C' = L XOR (R OR C)`.
    *   **Rationale:** Rule 30 is famous for its pseudo-random output from simple initial conditions and is computationally efficient.

### 2. Grid/World Structure

*   **Size:** Define a fixed size for the 1D grid, e.g., `CELLS = 256`.
*   **Boundary Conditions:** Use **fixed boundaries** (e.g., cells at the edges always considered "dead" or 0 when calculating neighbors) or **wrap-around (toroidal)**. Toroidal is slightly more common in CA studies for avoiding edge effects, but fixed boundaries are simpler.
*   **State Representation:** Each cell holds a single bit (`0` or `1`).

### 3. Seeding Mechanism

*   **Source:** The primary source of entropy for seeding will be the **encryption key (`K_e`)** and the **index of the data block (`i`)** being processed.
*   **Process:**
    1.  Combine the key and block index: `seed_input = H(K_e || i)` where `H` is a cryptographic hash function (e.g., SHA-256).
    2.  Take a sufficient number of bits from `seed_input` (e.g., the first `CELLS` bits) to initialize the 1D grid.
    3.  Set the initial state of the CA grid: `grid_initial[x] = bit_x_from_seed_input`.
    *   This ensures that each data block gets a unique, deterministic, key-dependent mask.

### 4. Evolution & Mask Generation

*   **Steps:** Define a fixed number of evolution steps `S` for the CA. This can be a configuration parameter or derived from the key (e.g., `S = (H(K_e || "steps") mod MAX_STEPS) + MIN_STEPS`). For simplicity, a fixed `S` (e.g., 100) is a good starting point.
*   **Process:**
    1.  Initialize the CA grid with the `grid_initial` state derived from the seed.
    2.  For `step` from 1 to `S`:
        a.  For each cell `x` (from 0 to `CELLS-1`):
            i.  Determine `L`, `C`, `R` (handling boundaries).
            ii.  Apply Rule 30: `temp_grid[x] = L XOR (R OR C)`.
        b.  Update the main `grid` with the states from `temp_grid`.
    3.  **Mask Extraction:** After `S` steps, the `grid` contains the final state. Extract bits from this final state to form the mask `M_i`.
        *   *Option 1 (Simple):* Use the entire final state of the grid as the mask. If the block size is less than `CELLS` bits, truncate the mask.
        *   *Option 2 (Flexible):* If a longer mask is needed, continue evolving the CA and concatenating bits from subsequent states until enough bits are collected.

### 5. Integration Point

This distilled CA engine will be implemented as a core module (e.g., `ca_prng.py` or `ca_engine.py`) within the packer project. It will provide a function like:

`generate_mask(key_material: bytes, block_index: int, mask_length: int) -> bytes`

This function will:
1.  Derive the seed from `key_material` and `block_index`.
2.  Initialize the CA grid.
3.  Run the CA for `S` steps.
4.  Extract and return a mask of `mask_length` bytes (or bits, handled appropriately).

This design is simple, efficient, leverages the good PRNG properties of Rule 30, and directly adapts the key-seeding concept from `l8burd`.
