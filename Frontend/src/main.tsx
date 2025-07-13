import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.scss'
import { createBrowserRouter, RouterProvider } from 'react-router-dom'
import Feed from './features/feed/pages/Feed';
import Login from './features/authentication/pages/Login/Login';
import SignUp from './features/authentication/pages/SignUp/SignUp';
import ResetPassword from './features/authentication/pages/ResetPassword/ResetPassword';
import VerifyEmail from './features/authentication/pages/VerifyEmail/VerifyEmail';

const router = createBrowserRouter([
  {
    path:"/",
    element:<Feed />,
  },
  {
    path:"/login",
    element:<Login />
  },
  {
    path:"/signup",
    element:<SignUp />
  },
  {
    path:"/request-password-rest",
    element: <ResetPassword />
  },
  {
    path:"/verify-email",
    element: <VerifyEmail />
  }
]);

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <RouterProvider router={router}>

    </RouterProvider>
  </StrictMode>,
)
