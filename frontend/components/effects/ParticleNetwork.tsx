'use client'

import { useRef, useMemo, useState, useEffect } from 'react'
import { Canvas, useFrame } from '@react-three/fiber'
import * as THREE from 'three'

const DESKTOP_NODES = 65
const MOBILE_NODES = 22
const CONNECTION_DIST = 2.2
const CONNECTION_DIST_SQ = CONNECTION_DIST * CONNECTION_DIST
const BOUNDS = 8
const MAX_CONNECTIONS = 120
const REPULSION_RADIUS = 3.5
const REPULSION_FORCE = 0.018

type NodeType = 'ip' | 'domain' | 'hash' | 'url'

type NodeData = {
  px: number; py: number; pz: number
  vx: number; vy: number; vz: number
  type: NodeType
}

const COLORS: Record<NodeType, [number, number, number]> = {
  ip:     [1.0, 0.18, 0.59],
  domain: [0.48, 0.24, 1.0],
  hash:   [1.0, 0.70, 0.24],
  url:    [0.18, 0.83, 0.75],
}

const TYPES: NodeType[] = ['ip', 'domain', 'hash', 'url']

function buildNodes(count: number): NodeData[] {
  return Array.from({ length: count }, () => {
    const type = TYPES[Math.floor(Math.random() * 4)]
    return {
      px: (Math.random() - 0.5) * BOUNDS * 2,
      py: (Math.random() - 0.5) * BOUNDS * 1.2,
      pz: (Math.random() - 0.5) * BOUNDS,
      vx: (Math.random() - 0.5) * 0.006,
      vy: (Math.random() - 0.5) * 0.006,
      vz: (Math.random() - 0.5) * 0.003,
      type,
    }
  })
}

function Network({ mobile }: { mobile: boolean }) {
  const groupRef = useRef<THREE.Group>(null)
  const nodeCount = mobile ? MOBILE_NODES : DESKTOP_NODES
  const nodes = useRef<NodeData[]>(buildNodes(nodeCount))

  // Pre-allocate all buffers once — zero GC pressure per frame
  const { pointsGeo, lineGeo, linePosArr, lineColArr } = useMemo(() => {
    const ns = nodes.current
    const pPos = new Float32Array(nodeCount * 3)
    const pCol = new Float32Array(nodeCount * 3)
    for (let i = 0; i < nodeCount; i++) {
      const n = ns[i]
      pPos[i * 3] = n.px; pPos[i * 3 + 1] = n.py; pPos[i * 3 + 2] = n.pz
      const c = COLORS[n.type]
      pCol[i * 3] = c[0]; pCol[i * 3 + 1] = c[1]; pCol[i * 3 + 2] = c[2]
    }

    const pg = new THREE.BufferGeometry()
    const pPosAttr = new THREE.BufferAttribute(pPos, 3)
    pPosAttr.setUsage(THREE.DynamicDrawUsage)
    pg.setAttribute('position', pPosAttr)
    pg.setAttribute('color', new THREE.BufferAttribute(pCol, 3))

    const maxPairs = Math.min(nodeCount * (nodeCount - 1) / 2, MAX_CONNECTIONS)
    const lPos = new Float32Array(maxPairs * 6)
    const lCol = new Float32Array(maxPairs * 6)
    const lg = new THREE.BufferGeometry()
    const lPosAttr = new THREE.BufferAttribute(lPos, 3)
    const lColAttr = new THREE.BufferAttribute(lCol, 3)
    lPosAttr.setUsage(THREE.DynamicDrawUsage)
    lColAttr.setUsage(THREE.DynamicDrawUsage)
    lg.setAttribute('position', lPosAttr)
    lg.setAttribute('color', lColAttr)
    lg.setDrawRange(0, 0)

    return { pointsGeo: pg, lineGeo: lg, linePosArr: lPos, lineColArr: lCol }
  }, [nodeCount])

  // Mobile throttle: target 30fps
  const lastTickRef = useRef(0)
  const TICK_MS = mobile ? 33 : 0

  useFrame(({ clock, pointer }) => {
    const now = performance.now()
    if (TICK_MS > 0 && now - lastTickRef.current < TICK_MS) return
    lastTickRef.current = now

    const t = clock.getElapsedTime()
    const ns = nodes.current

    // Pointer world-space position (pointer is -1..1 NDC)
    const mx = pointer.x * BOUNDS * 0.8
    const my = pointer.y * BOUNDS * 0.5

    for (let i = 0; i < nodeCount; i++) {
      const n = ns[i]

      // Apply repulsion from cursor/touch
      const rdx = n.px - mx
      const rdy = n.py - my
      const rDistSq = rdx * rdx + rdy * rdy
      if (rDistSq < REPULSION_RADIUS * REPULSION_RADIUS && rDistSq > 0.01) {
        const rDist = Math.sqrt(rDistSq)
        const f = REPULSION_FORCE * (1 - rDist / REPULSION_RADIUS)
        n.vx += (rdx / rDist) * f
        n.vy += (rdy / rDist) * f
      }

      // Dampen to prevent runaway
      n.vx *= 0.995
      n.vy *= 0.995
      n.vz *= 0.998

      n.px += n.vx
      n.py += n.vy
      n.pz += n.vz

      if (Math.abs(n.px) > BOUNDS)     n.vx *= -1
      if (Math.abs(n.py) > BOUNDS * 0.7) n.vy *= -1
      if (Math.abs(n.pz) > BOUNDS * 0.6) n.vz *= -1
    }

    // Update point positions in pre-allocated buffer
    const pAttr = pointsGeo.attributes.position as THREE.BufferAttribute
    for (let i = 0; i < nodeCount; i++) {
      const n = ns[i]
      pAttr.array[i * 3] = n.px
      pAttr.array[i * 3 + 1] = n.py
      pAttr.array[i * 3 + 2] = n.pz
    }
    pAttr.needsUpdate = true

    // Build connection lines in pre-allocated buffers — no new allocations
    let lineCount = 0
    outer: for (let i = 0; i < nodeCount; i++) {
      const ni = ns[i]
      for (let j = i + 1; j < nodeCount; j++) {
        if (lineCount >= MAX_CONNECTIONS) break outer
        const nj = ns[j]
        const dx = ni.px - nj.px
        const dy = ni.py - nj.py
        const dz = ni.pz - nj.pz
        const d2 = dx * dx + dy * dy + dz * dz
        if (d2 < CONNECTION_DIST_SQ) {
          const d = Math.sqrt(d2)
          const alpha = 1 - d / CONNECTION_DIST
          const ci = COLORS[ni.type]
          const cj = COLORS[nj.type]
          const b = lineCount * 6
          linePosArr[b]   = ni.px; linePosArr[b+1] = ni.py; linePosArr[b+2] = ni.pz
          linePosArr[b+3] = nj.px; linePosArr[b+4] = nj.py; linePosArr[b+5] = nj.pz
          lineColArr[b]   = ci[0] * alpha; lineColArr[b+1] = ci[1] * alpha; lineColArr[b+2] = ci[2] * alpha
          lineColArr[b+3] = cj[0] * alpha; lineColArr[b+4] = cj[1] * alpha; lineColArr[b+5] = cj[2] * alpha
          lineCount++
        }
      }
    }

    const lPosAttr = lineGeo.attributes.position as THREE.BufferAttribute
    const lColAttr = lineGeo.attributes.color as THREE.BufferAttribute
    lPosAttr.needsUpdate = true
    lColAttr.needsUpdate = true
    lineGeo.setDrawRange(0, lineCount * 2)

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
          size={0.08}
          sizeAttenuation
          transparent
          opacity={0.9}
          depthWrite={false}
        />
      </points>
      <lineSegments geometry={lineGeo}>
        <lineBasicMaterial vertexColors transparent opacity={0.22} depthWrite={false} />
      </lineSegments>
    </group>
  )
}

export default function ParticleNetwork({ className }: { className?: string }) {
  const [mobile, setMobile] = useState(false)

  useEffect(() => {
    const check = () =>
      window.innerWidth < 768 || /Mobi|Android/i.test(navigator.userAgent)
    setMobile(check())
  }, [])

  return (
    <div className={className} aria-hidden>
      <Canvas
        camera={{ position: [0, 0, 12], fov: 60 }}
        gl={{
          antialias: !mobile,
          alpha: true,
          powerPreference: 'high-performance',
          stencil: false,
          depth: false,
        }}
        dpr={[1, mobile ? 1.5 : 2]}
        style={{ background: 'transparent' }}
      >
        <Network mobile={mobile} />
      </Canvas>
    </div>
  )
}
