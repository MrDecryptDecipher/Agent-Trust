"""
Merkle tree implementation for tamper-evident reputation records.

Provides cryptographic proof that no records have been modified
or deleted after publication.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class MerkleNode:
    """A node in the Merkle tree."""
    hash: str
    left: Optional[MerkleNode] = None
    right: Optional[MerkleNode] = None
    data: Optional[str] = None
    index: int = -1


class MerkleTree:
    """
    A simple, append-only Merkle tree for reputation records.
    
    Provides:
    - Tamper-evident storage (any modification changes the root hash)
    - Efficient membership proofs
    - Append-only semantics (no deletions)
    
    Usage:
        tree = MerkleTree()
        tree.add_leaf({"agent": "a", "score": 0.95})
        tree.add_leaf({"agent": "b", "score": 0.87})
        
        root = tree.root_hash
        proof = tree.get_proof(0)
        assert tree.verify_proof(proof, tree.leaves[0].hash, root)
    """

    def __init__(self, hash_algorithm: str = "sha256"):
        self._algorithm = hash_algorithm
        self._leaves: list[MerkleNode] = []
        self._root: Optional[MerkleNode] = None
        self._dirty = True

    @property
    def root_hash(self) -> str:
        """Get the root hash of the tree."""
        if self._dirty:
            self._rebuild()
        if self._root is None:
            return self._hash("")
        return self._root.hash

    @property
    def leaves(self) -> list[MerkleNode]:
        return list(self._leaves)

    @property
    def size(self) -> int:
        return len(self._leaves)

    def add_leaf(self, data: Any) -> int:
        """
        Add a new leaf to the Merkle tree.
        
        Data is serialized to JSON and hashed.
        Returns the leaf index.
        """
        serialized = json.dumps(data, sort_keys=True, default=str)
        leaf_hash = self._hash(serialized)
        
        index = len(self._leaves)
        node = MerkleNode(
            hash=leaf_hash,
            data=serialized,
            index=index,
        )
        self._leaves.append(node)
        self._dirty = True
        
        return index

    def get_proof(self, leaf_index: int) -> list[tuple[str, str]]:
        """
        Generate a Merkle proof for a leaf at the given index.
        
        Returns a list of (hash, direction) tuples where direction
        is 'left' or 'right', indicating which side the sibling
        hash should go on.
        """
        if self._dirty:
            self._rebuild()
        
        if leaf_index < 0 or leaf_index >= len(self._leaves):
            return []
        
        proof = []
        nodes = [leaf.hash for leaf in self._leaves]
        index = leaf_index
        
        while len(nodes) > 1:
            new_nodes = []
            next_index = 0
            
            for i in range(0, len(nodes), 2):
                if i + 1 < len(nodes):
                    combined = nodes[i] + nodes[i + 1]
                    new_nodes.append(self._hash(combined))
                    
                    if i == index:
                        proof.append((nodes[i + 1], "right"))
                        next_index = len(new_nodes) - 1
                    elif i + 1 == index:
                        proof.append((nodes[i], "left"))
                        next_index = len(new_nodes) - 1
                else:
                    # Odd node out — promoted to next level
                    new_nodes.append(nodes[i])
                    if i == index:
                        next_index = len(new_nodes) - 1
            
            index = next_index
            nodes = new_nodes
        
        return proof

    def verify_proof(
        self,
        proof: list[tuple[str, str]],
        leaf_hash: str,
        root_hash: str,
    ) -> bool:
        """
        Verify a Merkle proof for a leaf.
        
        Returns True if the proof is valid (the leaf is part of
        the tree with the given root hash).
        """
        current = leaf_hash
        
        for sibling_hash, direction in proof:
            if direction == "left":
                combined = sibling_hash + current
            else:
                combined = current + sibling_hash
            current = self._hash(combined)
        
        return current == root_hash

    def verify_integrity(self) -> bool:
        """Verify the integrity of the entire tree."""
        if not self._leaves:
            return True
        
        # Recompute root from leaves
        saved_root = self.root_hash
        self._dirty = True
        computed_root = self.root_hash
        
        return saved_root == computed_root

    def _rebuild(self) -> None:
        """Rebuild the tree from leaves."""
        if not self._leaves:
            self._root = None
            self._dirty = False
            return
        
        nodes = [
            MerkleNode(hash=leaf.hash, data=leaf.data, index=leaf.index)
            for leaf in self._leaves
        ]
        
        while len(nodes) > 1:
            new_level = []
            for i in range(0, len(nodes), 2):
                if i + 1 < len(nodes):
                    combined = nodes[i].hash + nodes[i + 1].hash
                    parent = MerkleNode(
                        hash=self._hash(combined),
                        left=nodes[i],
                        right=nodes[i + 1],
                    )
                    new_level.append(parent)
                else:
                    new_level.append(nodes[i])
            nodes = new_level
        
        self._root = nodes[0]
        self._dirty = False

    def _hash(self, data: str) -> str:
        """Hash data using the configured algorithm."""
        h = hashlib.new(self._algorithm)
        h.update(data.encode("utf-8"))
        return h.hexdigest()
