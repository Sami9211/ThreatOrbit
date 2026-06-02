'use client'

import { useMemo, useRef, useState } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import { AdaptiveDpr, PerformanceMonitor } from '@react-three/drei'
import { EffectComposer, Bloom } from '@react-three/postprocessing'
import * as THREE from 'three'
import { usePerfProfile, useInViewport } from '@/lib/usePerf'

const TYPE_COLORS: Record<string, string> = {
  ip:     '#FF2E97',
  domain: '#7A3CFF',
  hash:   '#FFB23E',
  url:    '#2DD4BF',
  actor:  '#FF4D6D',
}

const TYPE_LIST = ['ip', 'domain', 'hash', 'url', 'actor']

function seededRNG(seed: number) {
  let s = seed
  return () => {
    s = Math.imul(1664525, s) + 1013904223 | 0
    return (s >>> 0) / 0x100000000
  }
}

function buildGraph(count: number) {
  const rng = seededRNG(42)

  // Cluster centers per type in 3D
  const clusterCenters: Record<string, THREE.Vector3> = {
    ip:     new THREE.Vector3( 2.8,  0.5,  0.2),
    domain: new THREE.Vector3(-2.2,  1.2, -0.5),
    hash:   new THREE.Vector3( 0.4, -2.0,  0.8),
    url:    new THREE.Vector3(-1.0,  0.2, -2.2),
    actor:  new THREE.Vector3( 0.8,  2.2,  0.5),
  }

  const nodes = Array.from({ length: count }, (_, i) => {
    const type = TYPE_LIST[i % TYPE_LIST.length]
    const center = clusterCenters[type]
    const spread = type === 'actor' ? 0.8 : 1.2
    return {
      id: i,
      type,
      color: TYPE_COLORS[type],
      pos: new THREE.Vector3(
        center.x + (rng() - 0.5) * spread * 2,
        center.y + (rng() - 0.5) * spread,
        center.z + (rng() - 0.5) * spread,
      ),
      size: type === 'actor' ? 0.09 : 0.04 + rng() * 0.04,
      pulse: rng(),
    }
  })

  // Edges: same-type nodes close to each other + cross-type actor edges
  const edges: Array<[number, number]> = []
  for (let a = 0; a < nodes.length; a++) {
    let connected = 0
    for (let b = a + 1; b < nodes.length; b++) {
      if (connected >= 3) break
      const na = nodes[a], nb = nodes[b]
      const dist = na.pos.distanceTo(nb.pos)
      const sameType = na.type === nb.type
      const actorEdge = na.type === 'actor' || nb.type === 'actor'
      if ((sameType && dist < 2.5) || (actorEdge && dist < 3.5 && rng() > 0.55)) {
        edges.push([a, b])
        connected++
      }
    }
  }

  return { nodes, edges }
}

function EdgeLines({ nodes, edges }: { nodes: ReturnType<typeof buildGraph>['nodes']; edges: Array<[number, number]> }) {
  const geom = useMemo(() => {
    const positions: number[] = []
    const colors: number[] = []
    edges.forEach(([a, b]) => {
      const pa = nodes[a].pos, pb = nodes[b].pos
      const ca = new THREE.Color(nodes[a].color)
      const cb = new THREE.Color(nodes[b].color)
      positions.push(pa.x, pa.y, pa.z, pb.x, pb.y, pb.z)
      colors.push(ca.r, ca.g, ca.b, cb.r, cb.g, cb.b)
    })
    const g = new THREE.BufferGeometry()
    g.setAttribute('position', new THREE.Float32BufferAttribute(positions, 3))
    g.setAttribute('color', new THREE.Float32BufferAttribute(colors, 3))
    return g
  }, [nodes, edges])

  return (
    <lineSegments geometry={geom}>
      <lineBasicMaterial vertexColors transparent opacity={0.18} toneMapped={false} />
    </lineSegments>
  )
}

function NodeMeshes({ nodes, animate }: { nodes: ReturnType<typeof buildGraph>['nodes']; animate: boolean }) {
  const meshRefs = useRef<(THREE.Mesh | null)[]>([])
  const t = useRef(0)

  useFrame((_, dt) => {
    if (!animate) return
    t.current += dt
    meshRefs.current.forEach((m, i) => {
      if (!m) return
      const node = nodes[i]
      const pulse = 0.85 + 0.18 * Math.sin(t.current * 1.4 + node.pulse * Math.PI * 2)
      m.scale.setScalar(pulse)
    })
  })

  return (
    <>
      {nodes.map((node, i) => (
        <mesh
          key={i}
          ref={(el) => { meshRefs.current[i] = el }}
          position={node.pos}
        >
          <sphereGeometry args={[node.size, 12, 12]} />
          <meshBasicMaterial
            color={node.color}
            toneMapped={false}
          />
        </mesh>
      ))}
    </>
  )
}

function SceneGroup({ nodeCount, animate }: { nodeCount: number; animate: boolean }) {
  const groupRef = useRef<THREE.Group>(null)
  const { nodes, edges } = useMemo(() => buildGraph(nodeCount), [nodeCount])

  useFrame((_, dt) => {
    if (groupRef.current && animate) {
      groupRef.current.rotation.y += dt * 0.05
      groupRef.current.rotation.x += dt * 0.015
    }
  })

  return (
    <group ref={groupRef}>
      <EdgeLines nodes={nodes} edges={edges} />
      <NodeMeshes nodes={nodes} animate={animate} />
    </group>
  )
}

export default function IOCNetworkScene() {
  const { prefersReducedMotion, isLowPower } = usePerfProfile()
  const { ref, visible } = useInViewport<HTMLDivElement>('200px')
  const [degraded, setDegraded] = useState(false)

  const animate   = !prefersReducedMotion
  const nodeCount = isLowPower ? 30 : 60
  const bloomOn   = !isLowPower && !degraded

  return (
    <div ref={ref} className="w-full h-full">
      <Canvas
        frameloop={visible && animate ? 'always' : 'demand'}
        camera={{ position: [0, 1, 8], fov: 52 }}
        gl={{ alpha: true, antialias: false, powerPreference: 'high-performance' }}
        dpr={degraded ? 1 : isLowPower ? [1, 1.25] : [1, 1.5]}
        style={{ background: 'transparent', width: '100%', height: '100%' }}
      >
        <ambientLight intensity={0.5} />
        <SceneGroup nodeCount={nodeCount} animate={animate} />
        {bloomOn && (
          <EffectComposer>
            <Bloom intensity={2.4} luminanceThreshold={0.05} luminanceSmoothing={0.88} mipmapBlur />
          </EffectComposer>
        )}
        <PerformanceMonitor onDecline={() => setDegraded(true)} />
        <AdaptiveDpr pixelated />
      </Canvas>
    </div>
  )
}
