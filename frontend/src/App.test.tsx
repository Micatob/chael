import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'

describe('smoke', () => {
  it('renders a node', () => {
    render(<div>hello</div>)
    expect(screen.getByText('hello')).toBeInTheDocument()
  })
})
