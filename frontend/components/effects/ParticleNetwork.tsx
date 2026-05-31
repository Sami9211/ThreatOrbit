'use client'

import { useRef, useMemo } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import * as THREE from 'three'

const NODE_COUNT = 90
const CONNECTION_DIST = 2.2
const BOUNDS = 8

type NodeData = {
  position: THREE.Vector3
  velocity: THREE.Vector3
  type: 'ip' | 'domain' | 'hash' | 'url'
}

function buildNodes(): NodeData[] {
  const types: NodeData['type'][] = ['ip', 'domain', 'hash', 'url']
  return Array.from({ length: NODE_COUNT }, () => ({
    position: new THREE.Vector3(
      (Math.random() - 0.5) * BOUNDS * 2,
      (Math.random() - 0.5) * BOUNDS * 1.2,
      (Math.random() - 0.5) * BOUNDS
    ),
    velocity: new THREE.Vector3(
      (Math.random() - 0.5) * 0.006,
      (Math.random() - 0.5) * 0.006,
      (Math.random() - 0.5) * 0.003
    ),
    type: types[Math.floor(Math.random() * 4)],
  }))
}

const TYPE_COLORS: Record<NodeData['type'], THREE.Color> = {
  ip: new THREE.Color('#00D4FF'),
  domain: new THREE.Color('#7B2FBE'),
  hash: new THREE.Color('#FF3366'),
  url: new THREE.Color('#00FF88'),
}

function Network() {
  const groupRef = useRef<THREE.Group>(null)
  const nodesRef = useRef<NodeData[]>(buildNodes())

  const { nodePositions, nodeColors } = useMemo(() => {
    const positions = new Float32Array(NODE_COUNT * 3)
    const colors = new Float32Array(NODE_COUNT * 3)
    nodesRef.current.forEach((n, i) => {
      positions[i * 3] = n.position.x
      positions[i * 3 + 1] = n.position.y
      positions[i * 3 + 2] = n.position.z
      const c = TYPE_COLORS[n.type]
      colors[i * 3] = c.r
      colors[i * 3 + 1] = c.g
      colors[i * 3 + 2] = c.b
    })
    return { nodePositions: positions, nodeColors: colors }
  }, [])

  const pointsGeo = useMemo(() => {
    const g = new THREE.BufferGeometry()
    g.setAttribute('position', new THREE.BufferAttribute(nodePositions, 3))
    g.setAttribute('color', new THREE.BufferAttribute(nodeColors, 3))
    return g
  }, [nodePositions, nodeColors])

  const lineGeo = useMemo(() => new THREE.BufferGeometry(), [])

  useFrame(({ clock }) => {
    const nodes = nodesRef.current
    const t = clock.getElapsedTime()

    // move nodes
    nodes.forEach((n) => {
      n.position.add(n.velocity)
      if (Math.abs(n.position.x) > BOUNDS) n.velocity.x *= -1
      if (Math.abs(n.position.y) > BOUNDS * 0.7) n.velocity.y *= -1
      if (Math.abs(n.position.z) > BOUNDS * 0.6) n.velocity.z *= -1
    })

    // update point positions
    const pos = pointsGeo.attributes.position as THREE.BufferAttribute
    nodes.forEach((n, i) => {
      pos.setXYZ(i, n.position.x, n.position.y, n.position.z)
    })
    pos.needsUpdate = true

    // rebuild connection lines
    const lineVerts: number[] = []
    const lineColors: number[] = []
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const d = nodes[i].position.distanceTo(nodes[j].position)
        if (d < CONNECTION_DIST) {
          const alpha = 1 - d / CONNECTION_DIST
          const ci = TYPE_COLORS[nodes[i].type]
          const cj = TYPE_COLORS[nodes[j].type]
          lineVerts.push(...nodes[i].position.toArray(), ...nodes[j].position.toArray())
          lineColors.push(ci.r * alpha, ci.g * alpha, ci.b * alpha,
                          cj.r * alpha, cj.g * alpha, cj.b * alpha)
        }
      }
    }
    lineGeo.setAttribute('position', new THREE.BufferAttribute(new Float32Array(lineVerts), 3))
    lineGeo.setAttribute('color', new THREE.BufferAttribute(new Float32Array(lineColors), 3))

    if (groupRef.current) {
      groupRef.current.rotation.y = t * 0.04
      groupRef.current.rotation.x = Math.sin(t * 0.02) * 0.08
    }
  })

  return (
    <group ref={groupRef}>
      <points geometry={pointsGeo}>
        <pointsMaterial
          vertexColors
          size={0.07}
          sizeAttenuation
          transparent
          opacity={0.9}
          depthWrite={false}
        />
      </points>
      <lineSegments geometry={lineGeo}>
        <lineBasicMaterial vertexColors transparent opacity={0.25} depthWrite={false} />
      </lineSegments>
    </group>
  )
}

export default function ParticleNetwork({ className }: { className?: string }) {
  return (
    <div className={className} aria-hidden>
      <Canvas
        camera={{ position: [0, 0, 12], fov: 60 }}
        gl={{ antialias: true, alpha: true }}
        style={{ background: 'transparent' }}
      >
        <Network />
      </Canvas>
    </div>
  )
}
